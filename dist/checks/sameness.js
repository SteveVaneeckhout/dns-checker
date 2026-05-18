import { createHash } from "node:crypto";
import { jaccardShingleSimilarity } from "../util/similarity.js";
async function firstAddress(dns, type, name) {
    const packet = await dns.query({ type, name });
    const answers = packet.answers ?? [];
    for (const a of answers) {
        if (a.type === type && typeof a.data === "string") {
            return a.data;
        }
    }
    return undefined;
}
async function fetchResponse(http, address, servername, url, timeoutMs, bodyLimit) {
    return http.get({ address, servername, url, timeoutMs, bodyLimit });
}
function hashResponse(res) {
    return createHash("sha256")
        .update(`${res.status}\n${res.headers["location"] ?? ""}\n`)
        .update(res.body)
        .digest("hex");
}
export async function runSamenessCheck(hostname, opts, dns, http) {
    const errors = [];
    const [v4, v6] = await Promise.all([
        firstAddress(dns, "A", hostname).catch((e) => {
            errors.push(`A lookup: ${e.message}`);
            return undefined;
        }),
        firstAddress(dns, "AAAA", hostname).catch((e) => {
            errors.push(`AAAA lookup: ${e.message}`);
            return undefined;
        }),
    ]);
    if (!v4 || !v6) {
        if (!v4)
            errors.push("no IPv4 address available");
        if (!v6)
            errors.push("no IPv6 address available");
        const base = {
            ok: false,
            errors,
            url: opts.url,
            match: false,
        };
        if (v4 !== undefined)
            base.ipv4Address = v4;
        if (v6 !== undefined)
            base.ipv6Address = v6;
        return base;
    }
    let ipv4Res;
    let ipv6Res;
    try {
        ipv4Res = await fetchResponse(http, v4, hostname, opts.url, opts.timeoutMs, opts.bodyHashLimit);
    }
    catch (e) {
        errors.push(`ipv4 fetch: ${e.message}`);
    }
    try {
        ipv6Res = await fetchResponse(http, v6, hostname, opts.url, opts.timeoutMs, opts.bodyHashLimit);
    }
    catch (e) {
        errors.push(`ipv6 fetch: ${e.message}`);
    }
    const result = {
        ok: false,
        errors,
        url: opts.url,
        ipv4Address: v4,
        ipv6Address: v6,
        match: false,
    };
    if (ipv4Res !== undefined &&
        ipv6Res !== undefined &&
        ipv4Res.status === 200 &&
        ipv6Res.status === 200) {
        result.similarity = jaccardShingleSimilarity(ipv4Res.body, ipv6Res.body);
        result.ok = errors.length === 0;
        return result;
    }
    const ipv4Hash = ipv4Res !== undefined ? hashResponse(ipv4Res) : undefined;
    const ipv6Hash = ipv6Res !== undefined ? hashResponse(ipv6Res) : undefined;
    if (ipv4Hash !== undefined)
        result.ipv4Hash = ipv4Hash;
    if (ipv6Hash !== undefined)
        result.ipv6Hash = ipv6Hash;
    result.match = ipv4Hash !== undefined && ipv6Hash !== undefined && ipv4Hash === ipv6Hash;
    result.ok = result.match && errors.length === 0;
    return result;
}
