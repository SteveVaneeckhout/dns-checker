import type { DnsTransport } from "./dns.js";
/**
 * Queries `name` and returns the data of every answer of `type` whose data is a string
 * (addresses for A/AAAA, host names for NS). Answers of other types, such as CNAMEs
 * along the way, are skipped.
 */
export declare function stringRecords(dns: DnsTransport, type: "A" | "AAAA" | "NS", name: string): Promise<string[]>;
