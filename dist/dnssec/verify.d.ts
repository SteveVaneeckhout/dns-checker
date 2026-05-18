import type { Answer, DnskeyData, RrsigData } from "dns-packet";
export declare function verifyRrsig(rrsig: RrsigData, rrset: Answer[], dnskeys: DnskeyData[]): boolean;
