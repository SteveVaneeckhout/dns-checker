import type { CaaData } from "dns-packet";
import type { DnsTransport } from "../net/dns.js";
import type { TlsTransport } from "../net/tls.js";
import type { CaaResult, ResolvedOptions } from "../types.js";
export declare function findCaaRecords(
  dns: DnsTransport,
  hostname: string,
): Promise<{
  zone: string;
  records: CaaData[];
}>;
export declare function issuerMatchesTag(
  issuer: string,
  tag: string,
): {
  matched: boolean;
  known: boolean;
};
export declare function runCaaCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  tls: TlsTransport,
): Promise<CaaResult>;
