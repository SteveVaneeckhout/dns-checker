import type { DnsTransport } from "../net/dns.js";
import type { TlsTransport } from "../net/tls.js";
import type { FamilyResult, IpResult, ResolvedOptions } from "../types.js";

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

async function probeReachable(
  tls: TlsTransport,
  address: string,
  servername: string,
  timeoutMs: number,
): Promise<boolean> {
  try {
    const r = await tls.handshake({ address, servername, timeoutMs });
    r.socket.destroy();
    return true;
  } catch {
    return false;
  }
}

async function probeFamily(
  dns: DnsTransport,
  tls: TlsTransport,
  host: string,
  type: "A" | "AAAA",
  timeoutMs: number,
): Promise<FamilyResult> {
  try {
    const addresses = await resolveAddrs(dns, type, host);
    if (addresses.length === 0) {
      return { addresses: [], reachable: false, error: "no address records" };
    }
    let reachable = false;
    for (const addr of addresses) {
      if (await probeReachable(tls, addr, host, timeoutMs)) {
        reachable = true;
        break;
      }
    }
    return { addresses, reachable };
  } catch (e) {
    return { addresses: [], reachable: false, error: (e as Error).message };
  }
}

export async function runIpCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  tls: TlsTransport,
): Promise<IpResult> {
  const [ipv4, ipv6] = await Promise.all([
    probeFamily(dns, tls, hostname, "A", opts.timeoutMs),
    probeFamily(dns, tls, hostname, "AAAA", opts.timeoutMs),
  ]);
  const errors: string[] = [];
  if (ipv4.error) errors.push(`ipv4: ${ipv4.error}`);
  if (ipv6.error) errors.push(`ipv6: ${ipv6.error}`);
  if (!ipv4.reachable) errors.push("ipv4: not reachable on 443");
  if (!ipv6.reachable) errors.push("ipv6: not reachable on 443");
  const ok = ipv4.reachable && ipv6.reachable;
  return { ok, errors, ipv4, ipv6 };
}
