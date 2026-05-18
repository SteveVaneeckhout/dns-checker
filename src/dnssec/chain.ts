import { Buffer } from "node:buffer";
import type { Answer, DnskeyData, DsData, RecordType, RrsigData } from "dns-packet";
import type { DnsTransport } from "../net/dns.js";
import { computeDsDigest, computeKeyTag } from "./canonical.js";
import { ROOT_TRUST_ANCHORS, type RootTrustAnchor } from "./rootKeys.js";
import { verifyRrsig } from "./verify.js";

export interface ChainValidationStep {
  zone: string;
  dsVerified: boolean;
  keysVerified: boolean;
}

export interface ChainResult {
  signed: boolean;
  chainValid: boolean;
  chain: ChainValidationStep[];
  errors: string[];
  finalZoneDnskeys: DnskeyData[];
  finalZone: string;
}

interface RrsetWithSig<T = Answer> {
  rrset: T[];
  rrsig: RrsigData | undefined;
}

function pickRrset<T extends Answer["type"]>(
  packet: { answers?: Answer[] | undefined },
  type: T,
  name: string,
): RrsetWithSig<Extract<Answer, { type: T }>> {
  const all = packet.answers ?? [];
  const lname = name.toLowerCase().replace(/\.$/, "");
  const matches = all.filter(
    (a) => a.type === type && a.name.toLowerCase().replace(/\.$/, "") === lname,
  ) as Extract<Answer, { type: T }>[];
  const rrsig = all.find(
    (a) =>
      a.type === "RRSIG" &&
      a.name.toLowerCase().replace(/\.$/, "") === lname &&
      a.data.typeCovered === type,
  ) as Extract<Answer, { type: "RRSIG" }> | undefined;
  return { rrset: matches, rrsig: rrsig?.data };
}

function dsMatches(ds: DsData, ownerName: string, dnskey: DnskeyData): boolean {
  if (computeKeyTag(dnskey) !== ds.keyTag) return false;
  if (dnskey.algorithm !== ds.algorithm) return false;
  let digest: Buffer;
  try {
    digest = computeDsDigest(ownerName, dnskey, ds.digestType);
  } catch {
    return false;
  }
  return Buffer.compare(digest, ds.digest) === 0;
}

function findZoneCuts(host: string): string[] {
  const labels = host.split(".").filter((l) => l.length > 0);
  const zones: string[] = ["."];
  for (let i = 1; i <= labels.length; i++) {
    zones.push(labels.slice(-i).join("."));
  }
  return zones;
}

async function fetchDnskeys(
  dns: DnsTransport,
  zone: string,
): Promise<RrsetWithSig<Extract<Answer, { type: "DNSKEY" }>>> {
  const queryName = zone === "." ? "." : zone;
  const packet = await dns.query({ type: "DNSKEY", name: queryName, dnssec: true });
  return pickRrset(packet, "DNSKEY", queryName);
}

async function fetchDs(
  dns: DnsTransport,
  zone: string,
): Promise<RrsetWithSig<Extract<Answer, { type: "DS" }>>> {
  const packet = await dns.query({ type: "DS", name: zone, dnssec: true });
  return pickRrset(packet, "DS", zone);
}

const MAX_CNAME_DEPTH = 8;

async function validateLeaf(
  host: string,
  parentKeys: DnskeyData[],
  dns: DnsTransport,
  anchors: readonly RootTrustAnchor[],
  errors: string[],
  depth: number,
): Promise<boolean> {
  if (depth >= MAX_CNAME_DEPTH) {
    errors.push(`CNAME chain depth limit (${MAX_CNAME_DEPTH}) exceeded at ${host}`);
    return false;
  }
  let packet: { answers?: Answer[] | undefined };
  try {
    packet = await dns.query({ type: "A", name: host, dnssec: true });
  } catch (e) {
    errors.push(`A query for ${host}: ${(e as Error).message}`);
    return false;
  }
  const cname = pickRrset(packet, "CNAME", host);
  if (cname.rrset.length > 0) {
    if (!cname.rrsig) {
      errors.push(`CNAME ${host} is unsigned`);
      return false;
    }
    const sigOk = verifyRrsig(cname.rrsig, cname.rrset as unknown as Answer[], parentKeys);
    if (!sigOk) {
      errors.push(`CNAME ${host} RRSIG did not verify`);
      return false;
    }
    const first = cname.rrset[0] as unknown as { data?: unknown } | undefined;
    const rawTarget = first?.data;
    if (typeof rawTarget !== "string") {
      errors.push(`CNAME ${host}: unparseable target`);
      return false;
    }
    const target = rawTarget.toLowerCase().replace(/\.$/, "");
    const targetResult = await validateChain(target, dns, anchors, depth + 1);
    if (!targetResult.signed) {
      for (const e of targetResult.errors) errors.push(`(resolving ${target}) ${e}`);
      errors.push(`CNAME ${host} -> ${target}: target is insecure (not in a signed zone)`);
      return false;
    }
    return true;
  }
  const a = pickRrset(packet, "A", host);
  if (a.rrset.length > 0) {
    if (!a.rrsig) {
      errors.push(`A ${host} is unsigned`);
      return false;
    }
    const sigOk = verifyRrsig(a.rrsig, a.rrset as unknown as Answer[], parentKeys);
    if (!sigOk) {
      errors.push(`A ${host} RRSIG did not verify`);
      return false;
    }
    return true;
  }
  return true;
}

export async function validateChain(
  host: string,
  dns: DnsTransport,
  anchors: readonly RootTrustAnchor[] = ROOT_TRUST_ANCHORS,
  depth: number = 0,
): Promise<ChainResult> {
  const result: ChainResult = {
    signed: false,
    chainValid: false,
    chain: [],
    errors: [],
    finalZoneDnskeys: [],
    finalZone: ".",
  };

  let rootKeys: DnskeyData[];
  try {
    const root = await fetchDnskeys(dns, ".");
    if (root.rrset.length === 0 || !root.rrsig) {
      result.errors.push("root DNSKEY RRset missing or unsigned");
      return result;
    }
    const rootKeyData = root.rrset.map((a) => a.data);
    const rootKsk = rootKeyData.find((k) =>
      anchors.some(
        (ta) =>
          computeKeyTag(k) === ta.keyTag &&
          k.algorithm === ta.algorithm &&
          Buffer.compare(
            computeDsDigest(".", k, ta.digestType),
            Buffer.from(ta.digestHex, "hex"),
          ) === 0,
      ),
    );
    if (!rootKsk) {
      result.errors.push("no root DNSKEY matches IANA trust anchor");
      return result;
    }
    const rootSigOk = verifyRrsig(
      root.rrsig,
      root.rrset.map((a) => ({ ...a, data: a.data }) as Answer),
      rootKeyData,
    );
    if (!rootSigOk) {
      result.errors.push("root DNSKEY RRSIG did not verify");
      return result;
    }
    rootKeys = rootKeyData;
    result.chain.push({ zone: ".", dsVerified: true, keysVerified: true });
  } catch (e) {
    result.errors.push(`root DNSKEY: ${(e as Error).message}`);
    return result;
  }

  const zones = findZoneCuts(host).filter((z) => z !== ".");
  let parentKeys = rootKeys;
  let parentZone = ".";
  let lastValidatedZone = ".";

  for (const child of zones) {
    let ds: RrsetWithSig<Extract<Answer, { type: "DS" }>>;
    try {
      ds = await fetchDs(dns, child);
    } catch (e) {
      result.errors.push(`DS query for ${child}: ${(e as Error).message}`);
      break;
    }
    if (ds.rrset.length === 0) {
      // no DS at this label — not a zone cut; keep going (parent stays the same)
      continue;
    }
    if (!ds.rrsig) {
      result.errors.push(`DS ${child} is unsigned`);
      break;
    }
    const dsOk = verifyRrsig(ds.rrsig, ds.rrset as unknown as Answer[], parentKeys);
    if (!dsOk) {
      result.errors.push(`DS ${child} RRSIG invalid under ${parentZone}`);
      break;
    }

    let dnskey: RrsetWithSig<Extract<Answer, { type: "DNSKEY" }>>;
    try {
      dnskey = await fetchDnskeys(dns, child);
    } catch (e) {
      result.errors.push(`DNSKEY query for ${child}: ${(e as Error).message}`);
      break;
    }
    if (dnskey.rrset.length === 0 || !dnskey.rrsig) {
      result.errors.push(`DNSKEY for ${child} missing or unsigned`);
      break;
    }
    const childKeyData = dnskey.rrset.map((a) => a.data);
    const matched = childKeyData.some((k) => ds.rrset.some((d) => dsMatches(d.data, child, k)));
    if (!matched) {
      result.errors.push(`no DNSKEY for ${child} matches DS from parent`);
      break;
    }
    const keysSig = verifyRrsig(dnskey.rrsig, dnskey.rrset as unknown as Answer[], childKeyData);
    if (!keysSig) {
      result.errors.push(`DNSKEY ${child} RRSIG invalid`);
      break;
    }
    result.chain.push({ zone: child, dsVerified: true, keysVerified: true });
    parentKeys = childKeyData;
    parentZone = child;
    lastValidatedZone = child;
  }

  let leafSecure = true;
  if (result.errors.length === 0 && result.chain.length > 1) {
    leafSecure = await validateLeaf(host, parentKeys, dns, anchors, result.errors, depth);
  }

  result.signed = result.chain.length > 1 && leafSecure;
  result.chainValid = result.errors.length === 0 && result.signed;
  result.finalZoneDnskeys = parentKeys;
  result.finalZone = lastValidatedZone;
  return result;
}

export async function verifyRecord(
  type: RecordType,
  name: string,
  dnskeys: DnskeyData[],
  dns: DnsTransport,
): Promise<{ verified: boolean; answers: Answer[]; error?: string }> {
  try {
    const packet = await dns.query({ type, name, dnssec: true });
    const got = pickRrset(packet, type as Answer["type"], name);
    if (got.rrset.length === 0) return { verified: false, answers: [], error: "no records" };
    if (!got.rrsig) return { verified: false, answers: got.rrset as Answer[], error: "no RRSIG" };
    const ok = verifyRrsig(got.rrsig, got.rrset as Answer[], dnskeys);
    return { verified: ok, answers: got.rrset as Answer[] };
  } catch (e) {
    return { verified: false, answers: [], error: (e as Error).message };
  }
}
