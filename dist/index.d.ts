import { type DnsTransport } from "./net/dns.js";
import { type HttpTransport } from "./net/http.js";
import { type TlsTransport } from "./net/tls.js";
import type {
  CaaResult,
  CheckOptions,
  CheckResult,
  DaneResult,
  DnssecResult,
  IpResult,
  NameserverResult,
  SamenessResult,
} from "./types.js";
export type * from "./types.js";
export interface CheckTransports {
  dns?: DnsTransport;
  tls?: TlsTransport;
  http?: HttpTransport;
}
export declare function checkIp(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<IpResult>;
export declare function checkNameservers(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<NameserverResult>;
export declare function checkSameness(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<SamenessResult>;
export declare function checkDnssec(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<DnssecResult>;
export declare function checkCaa(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<CaaResult>;
export declare function checkDane(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<DaneResult>;
export declare function checkDomain(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<CheckResult>;
