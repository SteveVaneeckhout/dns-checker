import type { DnsTransport } from "../net/dns.js";
import type { DnssecResult, ResolvedOptions } from "../types.js";
export declare function runDnssecCheck(hostname: string, opts: ResolvedOptions, dns: DnsTransport): Promise<DnssecResult>;
