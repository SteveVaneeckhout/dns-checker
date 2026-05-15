import { createHash } from "node:crypto";
import type { DnsTransport } from "../net/dns.js";
import type { HttpTransport } from "../net/http.js";
import type { ResolvedOptions, SamenessResult } from "../types.js";

async function firstAddress(
  dns: DnsTransport,
  type: "A" | "AAAA",
  name: string,
): Promise<string | undefined> {
  const packet = await dns.query({ type, name });
  const answers = packet.answers ?? [];
  for (const a of answers) {
    if (a.type === type && typeof (a as { data?: unknown }).data === "string") {
      return (a as unknown as { data: string }).data;
    }
  }
  return undefined;
}

async function responseHash(
  http: HttpTransport,
  address: string,
  servername: string,
  url: string,
  timeoutMs: number,
  bodyLimit: number,
): Promise<string> {
  const res = await http.get({ address, servername, url, timeoutMs, bodyLimit });
  return createHash("sha256")
    .update(`${res.status}\n${res.headers["location"] ?? ""}\n`)
    .update(res.body)
    .digest("hex");
}

export async function runSamenessCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  http: HttpTransport,
): Promise<SamenessResult> {
  const errors: string[] = [];
  const [v4, v6] = await Promise.all([
    firstAddress(dns, "A", hostname).catch((e: Error) => {
      errors.push(`A lookup: ${e.message}`);
      return undefined;
    }),
    firstAddress(dns, "AAAA", hostname).catch((e: Error) => {
      errors.push(`AAAA lookup: ${e.message}`);
      return undefined;
    }),
  ]);
  if (!v4 || !v6) {
    if (!v4) errors.push("no IPv4 address available");
    if (!v6) errors.push("no IPv6 address available");
    const base: SamenessResult = {
      ok: false,
      errors,
      url: opts.url,
      match: false,
    };
    if (v4 !== undefined) base.ipv4Address = v4;
    if (v6 !== undefined) base.ipv6Address = v6;
    return base;
  }
  let ipv4Hash: string | undefined;
  let ipv6Hash: string | undefined;
  try {
    ipv4Hash = await responseHash(http, v4, hostname, opts.url, opts.timeoutMs, opts.bodyHashLimit);
  } catch (e) {
    errors.push(`ipv4 fetch: ${(e as Error).message}`);
  }
  try {
    ipv6Hash = await responseHash(http, v6, hostname, opts.url, opts.timeoutMs, opts.bodyHashLimit);
  } catch (e) {
    errors.push(`ipv6 fetch: ${(e as Error).message}`);
  }
  const match = ipv4Hash !== undefined && ipv6Hash !== undefined && ipv4Hash === ipv6Hash;
  const result: SamenessResult = {
    ok: match && errors.length === 0,
    errors,
    url: opts.url,
    ipv4Address: v4,
    ipv6Address: v6,
    match,
  };
  if (ipv4Hash !== undefined) result.ipv4Hash = ipv4Hash;
  if (ipv6Hash !== undefined) result.ipv6Hash = ipv6Hash;
  return result;
}
