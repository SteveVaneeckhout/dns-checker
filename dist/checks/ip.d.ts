import type { DnsTransport } from "../net/dns.js";
import type { TlsTransport } from "../net/tls.js";
import type { IpResult, ResolvedOptions } from "../types.js";
export declare function runIpCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  tls: TlsTransport,
): Promise<IpResult>;
