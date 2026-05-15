import { Buffer } from "node:buffer";
import { generateKeyPairSync, KeyObject, sign as cryptoSign } from "node:crypto";
import type { Answer, DnskeyData, DsData, DecodedPacket, RrsigData } from "dns-packet";
import { computeDsDigest, computeKeyTag, rrsigSigningInput } from "../../src/dnssec/canonical.ts";
import type { RootTrustAnchor } from "../../src/dnssec/rootKeys.ts";

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export interface ZoneKeys {
  name: string;
  ksk: { dnskey: DnskeyData; priv: KeyObject };
  zsk: { dnskey: DnskeyData; priv: KeyObject };
  dnskeyAnswers: Answer[];
  dnskeySig: RrsigData;
}

function ed25519Dnskey(flags: number): { dnskey: DnskeyData; priv: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as unknown as { x: string };
  const dnskey: DnskeyData = { flags, algorithm: 15, key: b64urlDecode(jwk.x) };
  return { dnskey, priv: privateKey };
}

function signAnswers(
  rrset: Answer[],
  header: Omit<RrsigData, "signature">,
  priv: KeyObject,
): RrsigData {
  const fullHeader: RrsigData = { ...header, signature: Buffer.alloc(0) };
  const data = rrsigSigningInput(fullHeader, rrset);
  const signature = cryptoSign(null, data, priv) as Buffer;
  return { ...fullHeader, signature };
}

export function makeZone(name: string): ZoneKeys {
  const ksk = ed25519Dnskey(257);
  const zsk = ed25519Dnskey(256);
  const dnskeyAnswers: Answer[] = [
    { name, type: "DNSKEY", data: ksk.dnskey },
    { name, type: "DNSKEY", data: zsk.dnskey },
  ];
  const header = {
    typeCovered: "DNSKEY" as const,
    algorithm: 15,
    labels: name === "." ? 0 : name.split(".").filter((l) => l.length > 0).length,
    originalTTL: 3600,
    expiration: 0x70000000,
    inception: 0x60000000,
    keyTag: computeKeyTag(ksk.dnskey),
    signersName: name,
  };
  const dnskeySig = signAnswers(dnskeyAnswers, header, ksk.priv);
  return { name, ksk, zsk, dnskeyAnswers, dnskeySig };
}

export function signRrset(
  rrset: Answer[],
  typeCovered: Answer["type"],
  zone: ZoneKeys,
  ownerName: string,
): RrsigData {
  const labels = ownerName === "." ? 0 : ownerName.split(".").filter((l) => l.length > 0).length;
  const header = {
    typeCovered,
    algorithm: 15,
    labels,
    originalTTL: 3600,
    expiration: 0x70000000,
    inception: 0x60000000,
    keyTag: computeKeyTag(zone.zsk.dnskey),
    signersName: zone.name,
  };
  return signAnswers(rrset, header, zone.zsk.priv);
}

export function makeDsForChild(
  parentZone: ZoneKeys,
  childName: string,
  childZone: ZoneKeys,
): {
  records: Answer[];
  rrsig: RrsigData;
  ds: DsData;
} {
  const digest = computeDsDigest(childName, childZone.ksk.dnskey, 2);
  const ds: DsData = {
    keyTag: computeKeyTag(childZone.ksk.dnskey),
    algorithm: childZone.ksk.dnskey.algorithm,
    digestType: 2,
    digest,
  };
  const records: Answer[] = [{ name: childName, type: "DS", data: ds }];
  const rrsig = signRrset(records, "DS", parentZone, childName);
  return { records, rrsig, ds };
}

export function makeTrustAnchorFor(zone: ZoneKeys): RootTrustAnchor {
  const digest = computeDsDigest(".", zone.ksk.dnskey, 2);
  return {
    keyTag: computeKeyTag(zone.ksk.dnskey),
    algorithm: zone.ksk.dnskey.algorithm,
    digestType: 2,
    digestHex: digest.toString("hex").toUpperCase(),
  };
}

export type QueryHandler = (q: {
  type: string;
  name: string;
  dnssec?: boolean;
}) => DecodedPacket | Promise<DecodedPacket>;

export interface MockDnsTransport {
  query(opts: {
    type: string;
    name: string;
    dnssec?: boolean;
    server?: string;
    recursive?: boolean;
  }): Promise<DecodedPacket>;
}

export function buildPacket(answers: Answer[], rrsigs: RrsigData[]): DecodedPacket {
  const all: Answer[] = [...answers];
  for (const sig of rrsigs) {
    all.push({ name: answers[0]?.name ?? ".", type: "RRSIG", data: sig });
  }
  return {
    type: "response",
    flag_qr: true,
    flag_aa: false,
    flag_tc: false,
    flag_rd: true,
    flag_ra: true,
    flag_z: false,
    flag_ad: false,
    flag_cd: false,
    questions: [],
    answers: all,
    authorities: [],
    additionals: [],
  } as DecodedPacket;
}
