import type { Answer, DnskeyData, RecordType } from "dns-packet";
import type { DnsTransport } from "../net/dns.js";
import { type RootTrustAnchor } from "./rootKeys.js";
export interface ChainValidationStep {
    zone: string;
    dsVerified: boolean;
    keysVerified: boolean;
}
export interface ChainResult {
    signed: boolean;
    chainValid: boolean;
    chain: ChainValidationStep[];
    errors: string[];
    finalZoneDnskeys: DnskeyData[];
    finalZone: string;
}
export declare function validateChain(host: string, dns: DnsTransport, anchors?: readonly RootTrustAnchor[], depth?: number): Promise<ChainResult>;
export declare function verifyRecord(type: RecordType, name: string, dnskeys: DnskeyData[], dns: DnsTransport): Promise<{
    verified: boolean;
    answers: Answer[];
    error?: string;
}>;
