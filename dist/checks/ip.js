async function resolveAddrs(dns, type, name) {
  const packet = await dns.query({ type, name });
  const answers = packet.answers ?? [];
  const out = [];
  for (const a of answers) {
    if (a.type === type && typeof a.data === "string") {
      out.push(a.data);
    }
  }
  return out;
}
async function probeReachable(tls, address, servername, timeoutMs) {
  try {
    const r = await tls.handshake({ address, servername, timeoutMs });
    r.socket.destroy();
    return true;
  } catch {
    return false;
  }
}
async function probeFamily(dns, tls, host, type, timeoutMs) {
  try {
    const addresses = await resolveAddrs(dns, type, host);
    if (addresses.length === 0) {
      return { addresses: [], reachable: false, error: "no address records" };
    }
    let reachable = false;
    for (const addr of addresses) {
      if (await probeReachable(tls, addr, host, timeoutMs)) {
        reachable = true;
        break;
      }
    }
    return { addresses, reachable };
  } catch (e) {
    return { addresses: [], reachable: false, error: e.message };
  }
}
export async function runIpCheck(hostname, opts, dns, tls) {
  const [ipv4, ipv6] = await Promise.all([
    probeFamily(dns, tls, hostname, "A", opts.timeoutMs),
    probeFamily(dns, tls, hostname, "AAAA", opts.timeoutMs),
  ]);
  const errors = [];
  if (ipv4.error) errors.push(`ipv4: ${ipv4.error}`);
  if (ipv6.error) errors.push(`ipv6: ${ipv6.error}`);
  if (!ipv4.reachable) errors.push("ipv4: not reachable on 443");
  if (!ipv6.reachable) errors.push("ipv6: not reachable on 443");
  const ok = ipv4.reachable && ipv6.reachable;
  return { ok, errors, ipv4, ipv6 };
}
