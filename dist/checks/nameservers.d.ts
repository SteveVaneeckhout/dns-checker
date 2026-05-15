import type { DnsTransport } from "../net/dns.js";
import type { NameserverResult, ResolvedOptions } from "../types.js";
export declare function runNameserverCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
): Promise<NameserverResult>;
