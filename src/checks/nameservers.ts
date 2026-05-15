import type { DnsTransport } from "../net/dns.js";
import type { FamilyResult, NameserverEntry, NameserverResult, ResolvedOptions } from "../types.js";

async function resolveNamesAt(dns: DnsTransport, name: string): Promise<string[]> {
  const packet = await dns.query({ type: "NS", name });
  const answers = packet.answers ?? [];
  const out: string[] = [];
  for (const a of answers) {
    if (a.type === "NS" && typeof (a as { data?: unknown }).data === "string") {
      out.push((a as unknown as { data: string }).data);
    }
  }
  return out;
}

async function resolveApexNs(
  dns: DnsTransport,
  hostname: string,
): Promise<{ apex: string; names: string[] }> {
  let cur: string | undefined = hostname;
  while (cur) {
    const names = await resolveNamesAt(dns, cur);
    if (names.length > 0) return { apex: cur, names };
    const idx = cur.indexOf(".");
    if (idx === -1) break;
    cur = cur.slice(idx + 1);
  }
  return { apex: hostname, names: [] };
}

async function resolveAddrs(
  dns: DnsTransport,
  type: "A" | "AAAA",
  name: string,
): Promise<string[]> {
  const packet = await dns.query({ type, name });
  const answers = packet.answers ?? [];
  const out: string[] = [];
  for (const a of answers) {
    if (a.type === type && typeof (a as { data?: unknown }).data === "string") {
      out.push((a as unknown as { data: string }).data);
    }
  }
  return out;
}

async function probeNs(
  dns: DnsTransport,
  address: string,
  apex: string,
  timeoutMs: number,
): Promise<boolean> {
  try {
    const packet = await dns.query({
      type: "SOA",
      name: apex,
      server: address,
      timeoutMs,
      recursive: false,
    });
    return packet.type === "response";
  } catch {
    return false;
  }
}

async function probeFamily(
  dns: DnsTransport,
  nsName: string,
  apex: string,
  type: "A" | "AAAA",
  timeoutMs: number,
): Promise<FamilyResult> {
  try {
    const addresses = await resolveAddrs(dns, type, nsName);
    if (addresses.length === 0) {
      return { addresses: [], reachable: false, error: "no address records" };
    }
    let reachable = false;
    for (const addr of addresses) {
      if (await probeNs(dns, addr, apex, timeoutMs)) {
        reachable = true;
        break;
      }
    }
    return { addresses, reachable };
  } catch (e) {
    return { addresses: [], reachable: false, error: (e as Error).message };
  }
}

export async function runNameserverCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
): Promise<NameserverResult> {
  const errors: string[] = [];
  let resolved: { apex: string; names: string[] };
  try {
    resolved = await resolveApexNs(dns, hostname);
  } catch (e) {
    return {
      ok: false,
      errors: [`NS query failed: ${(e as Error).message}`],
      nameservers: [],
    };
  }
  if (resolved.names.length === 0) {
    return { ok: false, errors: ["no NS records found"], nameservers: [] };
  }
  const apex = resolved.apex;
  const nameservers: NameserverEntry[] = await Promise.all(
    resolved.names.map(async (name) => {
      const [ipv4, ipv6] = await Promise.all([
        probeFamily(dns, name, apex, "A", opts.timeoutMs),
        probeFamily(dns, name, apex, "AAAA", opts.timeoutMs),
      ]);
      return { name, ipv4, ipv6 };
    }),
  );
  let ok = true;
  for (const ns of nameservers) {
    if (!ns.ipv4.reachable) {
      errors.push(`${ns.name}: not reachable over IPv4`);
      ok = false;
    }
    if (!ns.ipv6.reachable) {
      errors.push(`${ns.name}: not reachable over IPv6`);
      ok = false;
    }
  }
  return { ok, errors, nameservers };
}
