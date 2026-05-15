import type { TlsaData } from "dns-packet";
import type { DetailedPeerCertificate } from "node:tls";
import type { DnsTransport } from "../net/dns.js";
import type { TlsTransport } from "../net/tls.js";
import type { DaneResult, DnssecResult, ResolvedOptions } from "../types.js";
export declare function tlsaMatches(
  record: TlsaData,
  leaf: DetailedPeerCertificate,
  chain: DetailedPeerCertificate[],
): boolean;
export declare function runDaneCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  tlsT: TlsTransport,
  dnssec?: DnssecResult,
): Promise<DaneResult>;
