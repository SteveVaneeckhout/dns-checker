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
  /**
   * URL every redirect chain must end at, e.g. `https://www.example.com/`. Default: the URL
   * most chains end at.
   */
  canonicalUrl?: string;
}

export interface ResolvedOptions {
  url: string;
  timeoutMs: number;
  resolver: string;
  bodyHashLimit: number;
  trustAnchors?: readonly RootTrustAnchorRef[];
  canonicalUrl?: string;
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
  similarity?: number;
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

export interface RedirectHop {
  url: string;
  /** IP address the request was sent to. */
  address: string;
  status: number;
  /** The `Location` header, as sent. */
  location?: string;
}

export interface RedirectChain {
  /** One of `http://apex/`, `http://www/`, `https://apex/`, `https://www/`. */
  startUrl: string;
  hops: RedirectHop[];
  /** URL of the last response that was fetched. */
  finalUrl?: string;
  finalStatus?: number;
  errors: string[];
  warnings: string[];
}

export interface RedirectFamilyResult {
  /** False when neither the apex nor the www name has an address in this family. */
  available: boolean;
  chains: RedirectChain[];
}

export interface RedirectResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  apex: string;
  www: string;
  /** The URL every chain should end at: `canonicalUrl` option, else the most common final URL. */
  canonicalUrl?: string;
  ipv4: RedirectFamilyResult;
  ipv6: RedirectFamilyResult;
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
  redirects: RedirectResult;
}
