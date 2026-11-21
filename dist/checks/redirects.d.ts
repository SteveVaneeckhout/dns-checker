import type { DnsTransport } from "../net/dns.js";
import { type HttpTransport } from "../net/http.js";
import type { RedirectResult, ResolvedOptions } from "../types.js";
/** `example.com` and `www.example.com`, whichever of the two `hostname` is. */
export declare function apexAndWww(hostname: string): {
    apex: string;
    www: string;
};
/** The four entry points: http/https × apex/www. */
export declare function startUrls(apex: string, www: string): string[];
export declare function runRedirectCheck(hostname: string, opts: ResolvedOptions, dns: DnsTransport, http: HttpTransport): Promise<RedirectResult>;
