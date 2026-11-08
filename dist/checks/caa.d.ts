import type { CaaData } from "dns-packet";
import type { DnsTransport } from "../net/dns.js";
import type { TlsTransport } from "../net/tls.js";
import type { CaaResult, ResolvedOptions } from "../types.js";
export declare function findCaaRecords(dns: DnsTransport, hostname: string): Promise<{
    zone: string;
    records: CaaData[];
}>;
export declare function issuerMatchesTag(issuer: string, tag: string): {
    matched: boolean;
    known: boolean;
};
/**
 * The certificate name that covers `hostname`, and where its CAA search starts (RFC 8659 §3):
 * at the hostname for an exact name, at the parent for a `*.parent` wildcard. Uses the DNS
 * subjectAltNames, or the subject CN when the certificate has none. An exact name wins over a
 * wildcard, because a CA checks each name in the certificate on its own. Undefined when no name
 * covers the hostname.
 */
export declare function coveringName(hostname: string, sans: readonly string[], subjectCN: string): {
    wildcard: boolean;
    lookupFrom: string;
} | undefined;
export declare function runCaaCheck(hostname: string, opts: ResolvedOptions, dns: DnsTransport, tls: TlsTransport): Promise<CaaResult>;
