import type { CaaData } from "dns-packet";
import type { DnsTransport } from "../net/dns.js";
import type { TlsTransport } from "../net/tls.js";
import { certIssuerString, certSubjectCN } from "../net/tls.js";
import type { CaaRecord, CaaResult, ResolvedOptions } from "../types.js";

const CA_TAG_MAP: Record<string, string[]> = {
  "letsencrypt.org": ["Let's Encrypt"],
  "digicert.com": ["DigiCert"],
  "sectigo.com": ["Sectigo", "Comodo", "ZeroSSL"],
  "comodoca.com": ["Sectigo", "Comodo"],
  "globalsign.com": ["GlobalSign"],
  "godaddy.com": ["GoDaddy", "Go Daddy", "Starfield"],
  "starfieldtech.com": ["Starfield"],
  "amazontrust.com": ["Amazon"],
  "amazon.com": ["Amazon"],
  "pki.goog": ["Google Trust Services", "GTS"],
  "google.com": ["Google Trust Services", "GTS"],
  "buypass.com": ["Buypass"],
  "buypass.no": ["Buypass"],
  "entrust.net": ["Entrust"],
  "ssl.com": ["SSL.com", "SSL Corp"],
  "certum.pl": ["Certum", "Asseco", "Unizeto"],
};

function parentZone(name: string): string | undefined {
  const idx = name.indexOf(".");
  if (idx === -1) return undefined;
  return name.slice(idx + 1);
}

async function fetchCaa(
  dns: DnsTransport,
  zone: string,
): Promise<{ zone: string; records: CaaData[] }> {
  const packet = await dns.query({ type: "CAA", name: zone });
  const records = (packet.answers ?? [])
    .filter((a) => a.type === "CAA")
    .map((a) => a.data as CaaData);
  return { zone, records };
}

export async function findCaaRecords(
  dns: DnsTransport,
  hostname: string,
): Promise<{ zone: string; records: CaaData[] }> {
  let cur: string | undefined = hostname;
  while (cur) {
    try {
      const r = await fetchCaa(dns, cur);
      if (r.records.length > 0) return r;
    } catch {
      // continue walking up
    }
    cur = parentZone(cur);
  }
  return { zone: hostname, records: [] };
}

export function issuerMatchesTag(
  issuer: string,
  tag: string,
): { matched: boolean; known: boolean } {
  const cleaned = tag.trim().split(";")[0]?.trim().toLowerCase() ?? "";
  if (cleaned === "") return { matched: false, known: true };
  const aliases = CA_TAG_MAP[cleaned];
  if (!aliases) return { matched: false, known: false };
  const lower = issuer.toLowerCase();
  for (const alias of aliases) {
    if (lower.includes(alias.toLowerCase())) return { matched: true, known: true };
  }
  return { matched: false, known: true };
}

export async function runCaaCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  tls: TlsTransport,
): Promise<CaaResult> {
  const errors: string[] = [];
  let caa: { zone: string; records: CaaData[] };
  try {
    caa = await findCaaRecords(dns, hostname);
  } catch (e) {
    return {
      ok: false,
      errors: [`CAA lookup: ${(e as Error).message}`],
      records: [],
    };
  }
  const recordList: CaaRecord[] = caa.records.map((r) => ({
    zone: caa.zone,
    flags: r.flags ?? (r.issuerCritical ? 128 : 0),
    tag: r.tag,
    value: r.value,
  }));
  if (recordList.length === 0) {
    return { ok: true, errors: [], records: [] };
  }

  let issuer = "";
  let isWild = false;
  try {
    const r = await tls.handshake({
      address: hostname,
      servername: hostname,
      timeoutMs: opts.timeoutMs,
    });
    r.socket.destroy();
    issuer = certIssuerString(r.leaf);
    const subj = certSubjectCN(r.leaf);
    isWild = subj.startsWith("*.");
  } catch (e) {
    errors.push(`TLS handshake: ${(e as Error).message}`);
    return { ok: false, errors, records: recordList };
  }

  const relevant = recordList.filter((r) =>
    isWild ? r.tag === "issuewild" || r.tag === "issue" : r.tag === "issue",
  );
  if (relevant.length === 0) {
    errors.push("no applicable issue/issuewild directive");
    return { ok: false, errors, records: recordList, certIssuer: issuer };
  }
  for (const rec of relevant) {
    const m = issuerMatchesTag(issuer, rec.value);
    if (!m.known) {
      errors.push(`unknown CA tag: ${rec.value.split(";")[0]}`);
      continue;
    }
    if (m.matched) {
      const matchedTag = rec.value.split(";")[0]?.trim();
      return {
        ok: true,
        errors,
        records: recordList,
        certIssuer: issuer,
        ...(matchedTag !== undefined ? { matchedTag } : {}),
      };
    }
  }
  errors.push(`certificate issuer '${issuer}' not permitted by CAA`);
  return { ok: false, errors, records: recordList, certIssuer: issuer };
}
