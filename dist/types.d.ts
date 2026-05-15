export interface RootTrustAnchorRef {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digestHex: string;
}
export interface CheckOptions {
  url?: string;
  timeoutMs?: number;
  resolver?: string;
  bodyHashLimit?: number;
  trustAnchors?: readonly RootTrustAnchorRef[];
}
export interface ResolvedOptions {
  url: string;
  timeoutMs: number;
  resolver: string;
  bodyHashLimit: number;
  trustAnchors?: readonly RootTrustAnchorRef[];
}
export interface FamilyResult {
  addresses: string[];
  reachable: boolean;
  error?: string;
}
export interface IpResult {
  ok: boolean;
  errors: string[];
  ipv4: FamilyResult;
  ipv6: FamilyResult;
}
export interface NameserverEntry {
  name: string;
  ipv4: FamilyResult;
  ipv6: FamilyResult;
}
export interface NameserverResult {
  ok: boolean;
  errors: string[];
  nameservers: NameserverEntry[];
}
export interface SamenessResult {
  ok: boolean;
  errors: string[];
  url: string;
  ipv4Address?: string;
  ipv6Address?: string;
  ipv4Hash?: string;
  ipv6Hash?: string;
  match: boolean;
}
export interface DnssecChainStep {
  zone: string;
  dsVerified: boolean;
  keysVerified: boolean;
}
export interface DnssecResult {
  ok: boolean;
  errors: string[];
  signed: boolean;
  chainValid: boolean;
  chain: DnssecChainStep[];
}
export interface CaaRecord {
  zone: string;
  flags: number;
  tag: string;
  value: string;
}
export interface CaaResult {
  ok: boolean;
  errors: string[];
  records: CaaRecord[];
  certIssuer?: string;
  matchedTag?: string;
}
export interface TlsaRecord {
  usage: number;
  selector: number;
  matchingType: number;
  data: string;
}
export interface DaneResult {
  ok: boolean;
  errors: string[];
  records: TlsaRecord[];
  matched: boolean;
  matchedRecord?: TlsaRecord;
}
export interface CheckResult {
  hostname: string;
  startedAt: string;
  durationMs: number;
  ip: IpResult;
  nameservers: NameserverResult;
  sameness: SamenessResult;
  dnssec: DnssecResult;
  caa: CaaResult;
  dane: DaneResult;
}
