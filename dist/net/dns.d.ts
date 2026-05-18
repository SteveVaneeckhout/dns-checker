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
export declare function queryUdp(query: Buffer, server: string, port: number, timeoutMs: number): Promise<Buffer>;
export declare function queryTcp(query: Buffer, server: string, port: number, timeoutMs: number): Promise<Buffer>;
export declare function createDnsTransport(defaults: DnsTransportDefaults): DnsTransport;
