import { runCaaCheck } from "./checks/caa.js";
import { runDaneCheck } from "./checks/dane.js";
import { runDnssecCheck } from "./checks/dnssec.js";
import { runIpCheck } from "./checks/ip.js";
import { runNameserverCheck } from "./checks/nameservers.js";
import { runSamenessCheck } from "./checks/sameness.js";
import { createDnsTransport } from "./net/dns.js";
import { createHttpTransport } from "./net/http.js";
import { createTlsTransport } from "./net/tls.js";
import { normalizeHostname, resolveOptions } from "./options.js";
function buildTransports(host, opts, override) {
  void host;
  return {
    dns:
      override?.dns ?? createDnsTransport({ resolver: opts.resolver, timeoutMs: opts.timeoutMs }),
    tls: override?.tls ?? createTlsTransport(),
    http: override?.http ?? createHttpTransport(),
  };
}
export async function checkIp(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runIpCheck(hostname, opts, t.dns, t.tls);
}
export async function checkNameservers(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runNameserverCheck(hostname, opts, t.dns);
}
export async function checkSameness(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runSamenessCheck(hostname, opts, t.dns, t.http);
}
export async function checkDnssec(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runDnssecCheck(hostname, opts, t.dns);
}
export async function checkCaa(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runCaaCheck(hostname, opts, t.dns, t.tls);
}
export async function checkDane(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  return runDaneCheck(hostname, opts, t.dns, t.tls);
}
export async function checkDomain(host, options, transports) {
  const hostname = normalizeHostname(host);
  const opts = resolveOptions(hostname, options);
  const t = buildTransports(hostname, opts, transports);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const [ip, nameservers, sameness, dnssec, caa] = await Promise.all([
    runIpCheck(hostname, opts, t.dns, t.tls),
    runNameserverCheck(hostname, opts, t.dns),
    runSamenessCheck(hostname, opts, t.dns, t.http),
    runDnssecCheck(hostname, opts, t.dns),
    runCaaCheck(hostname, opts, t.dns, t.tls),
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
  };
}
