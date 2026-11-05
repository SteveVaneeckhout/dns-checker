import { stringRecords } from "../net/records.js";
import { errorMessage } from "../util/errors.js";
async function resolveApexNs(dns, hostname) {
    let cur = hostname;
    while (cur) {
        const names = await stringRecords(dns, "NS", cur);
        if (names.length > 0)
            return { apex: cur, names };
        const idx = cur.indexOf(".");
        if (idx === -1)
            break;
        cur = cur.slice(idx + 1);
    }
    return { apex: hostname, names: [] };
}
async function probeNs(dns, address, apex, timeoutMs) {
    try {
        const packet = await dns.query({
            type: "SOA",
            name: apex,
            server: address,
            timeoutMs,
            recursive: false,
        });
        return packet.type === "response";
    }
    catch {
        return false;
    }
}
async function probeFamily(dns, nsName, apex, type, timeoutMs) {
    try {
        const addresses = await stringRecords(dns, type, nsName);
        if (addresses.length === 0) {
            return { addresses: [], reachable: false, error: "no address records" };
        }
        let reachable = false;
        for (const addr of addresses) {
            if (await probeNs(dns, addr, apex, timeoutMs)) {
                reachable = true;
                break;
            }
        }
        return { addresses, reachable };
    }
    catch (e) {
        return { addresses: [], reachable: false, error: errorMessage(e) };
    }
}
export async function runNameserverCheck(hostname, opts, dns) {
    const errors = [];
    let resolved;
    try {
        resolved = await resolveApexNs(dns, hostname);
    }
    catch (e) {
        return {
            ok: false,
            errors: [`NS query failed: ${errorMessage(e)}`],
            nameservers: [],
        };
    }
    if (resolved.names.length === 0) {
        return { ok: false, errors: ["no NS records found"], nameservers: [] };
    }
    const apex = resolved.apex;
    const nameservers = await Promise.all(resolved.names.map(async (name) => {
        const [ipv4, ipv6] = await Promise.all([
            probeFamily(dns, name, apex, "A", opts.timeoutMs),
            probeFamily(dns, name, apex, "AAAA", opts.timeoutMs),
        ]);
        return { name, ipv4, ipv6 };
    }));
    let ok = true;
    for (const ns of nameservers) {
        if (!ns.ipv4.reachable) {
            errors.push(`${ns.name}: not reachable over IPv4`);
            ok = false;
        }
        if (!ns.ipv6.reachable) {
            errors.push(`${ns.name}: not reachable over IPv6`);
            ok = false;
        }
    }
    return { ok, errors, nameservers };
}
