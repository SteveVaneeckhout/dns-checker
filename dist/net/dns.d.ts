import { Buffer } from "node:buffer";
import type { DecodedPacket, RecordType } from "dns-packet";
export interface DnsQueryOptions {
    type: RecordType;
    name: string;
    server?: string;
    port?: number;
    timeoutMs?: number;
    dnssec?: boolean;
    recursive?: boolean;
}
export interface DnsTransport {
    query(opts: DnsQueryOptions): Promise<DecodedPacket>;
}
export interface DnsTransportDefaults {
    resolver: string;
    timeoutMs: number;
}
/** A DNS query got no (matching) answer within its time limit. */
export declare class DnsTimeoutError extends Error {
    readonly name = "DnsTimeoutError";
}
/**
 * Sends `query` over UDP and resolves with the first reply that carries the same ID.
 * Rejects with `DnsTimeoutError` if none arrives within `timeoutMs`.
 */
export declare function queryUdp(query: Buffer, server: string, port: number, timeoutMs: number): Promise<Buffer>;
/**
 * Sends `query` over TCP (2-byte length prefix, RFC 1035 §4.2.2) and resolves with the
 * reply. Rejects with `DnsTimeoutError` if it doesn't complete within `timeoutMs`.
 */
export declare function queryTcp(query: Buffer, server: string, port: number, timeoutMs: number): Promise<Buffer>;
export declare function createDnsTransport(defaults: DnsTransportDefaults): DnsTransport;
