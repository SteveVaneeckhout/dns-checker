import type { DnsTransport } from "../net/dns.js";
import type { HttpTransport } from "../net/http.js";
import type { ResolvedOptions, SamenessResult } from "../types.js";
export declare function runSamenessCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  http: HttpTransport,
): Promise<SamenessResult>;
