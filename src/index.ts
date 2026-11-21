import { runCaaCheck } from "./checks/caa.js";
import { runDaneCheck } from "./checks/dane.js";
import { runDnssecCheck } from "./checks/dnssec.js";
import { runIpCheck } from "./checks/ip.js";
import { runNameserverCheck } from "./checks/nameservers.js";
import { runRedirectCheck } from "./checks/redirects.js";
import { runSamenessCheck } from "./checks/sameness.js";
import { createDnsTransport, type DnsTransport } from "./net/dns.js";
import { createHttpTransport, type HttpTransport } from "./net/http.js";
import { createTlsTransport, type TlsTransport } from "./net/tls.js";
import { normalizeHostname, resolveOptions } from "./options.js";
import type {
  CaaResult,
  CheckOptions,
  CheckResult,
  DaneResult,
  DnssecResult,
  IpResult,
  NameserverResult,
  RedirectResult,
  SamenessResult,
} from "./types.js";

export type * from "./types.js";

export interface CheckTransports {
  dns?: DnsTransport;
  tls?: TlsTransport;
  http?: HttpTransport;
}

function buildTransports(
  host: string,
  opts: ReturnType<typeof resolveOptions>,
  override?: CheckTransports,
): { dns: DnsTransport; tls: TlsTransport; http: HttpTransport } {
  void host;
  return {
    dns:
      override?.dns ?? createDnsTransport({ resolver: opts.resolver, timeoutMs: opts.timeoutMs }),
    tls: override?.tls ?? createTlsTransport(),
    http: override?.http ?? createHttpTransport(),
  };
}

export async function checkIp(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<IpResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runIpCheck(hostname, opts, t.dns, t.tls);
}

export async function checkNameservers(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<NameserverResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runNameserverCheck(hostname, opts, t.dns);
}

export async function checkSameness(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<SamenessResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runSamenessCheck(hostname, opts, t.dns, t.http);
}

export async function checkDnssec(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<DnssecResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runDnssecCheck(hostname, opts, t.dns);
}

export async function checkCaa(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<CaaResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runCaaCheck(hostname, opts, t.dns, t.tls);
}

export async function checkDane(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<DaneResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runDaneCheck(hostname, opts, t.dns, t.tls);
}

export async function checkRedirects(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<RedirectResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runRedirectCheck(hostname, opts, t.dns, t.http);
}

export async function checkDomain(
  host: string,
  options?: CheckOptions,
  transports?: CheckTransports,
): Promise<CheckResult> {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const [ip, nameservers, sameness, dnssec, caa, redirects] = await Promise.all([
    runIpCheck(hostname, opts, t.dns, t.tls),
    runNameserverCheck(hostname, opts, t.dns),
    runSamenessCheck(hostname, opts, t.dns, t.http),
    runDnssecCheck(hostname, opts, t.dns),
    runCaaCheck(hostname, opts, t.dns, t.tls),
    runRedirectCheck(hostname, opts, t.dns, t.http),
  ]);
  const dane = await runDaneCheck(hostname, opts, t.dns, t.tls, dnssec);
  return {
    hostname,
    startedAt,
    durationMs: Date.now() - t0,
    ip,
    nameservers,
    sameness,
    dnssec,
    caa,
    dane,
    redirects,
  };
}
