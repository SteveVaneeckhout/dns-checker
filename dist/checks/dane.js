import { Buffer } from "node:buffer";
import { hash, X509Certificate } from "node:crypto";
import { validateChain, verifyRecord } from "../dnssec/chain.js";
import { ROOT_TRUST_ANCHORS } from "../dnssec/rootKeys.js";
import { errorMessage } from "../util/errors.js";
function selectorData(cert, selector) {
    if (selector === 0) {
        return cert.raw;
    }
    if (selector === 1) {
        // SubjectPublicKeyInfo DER (RFC 6698 §2.1.2). Node's `cert.pubkey` is only the bare
        // key (e.g. the EC point), so its hash never equals a published "x 1 x" TLSA record.
        try {
            return new X509Certificate(cert.raw).publicKey.export({ type: "spki", format: "der" });
        }
        catch {
            return undefined;
        }
    }
    return undefined;
}
function matchData(data, matchingType) {
    if (matchingType === 0)
        return data;
    if (matchingType === 1)
        return hash("sha256", data, "buffer");
    if (matchingType === 2)
        return hash("sha512", data, "buffer");
    return undefined;
}
function tlsaCertsForUsage(usage, leaf, chain) {
    if (usage === 1 || usage === 3)
        return [leaf];
    if (usage === 0 || usage === 2)
        return chain.slice(1);
    return [];
}
export function tlsaMatches(record, leaf, chain) {
    const certs = tlsaCertsForUsage(record.usage, leaf, chain);
    for (const cert of certs) {
        const sel = selectorData(cert, record.selector);
        if (!sel)
            continue;
        const m = matchData(sel, record.matchingType);
        if (!m)
            continue;
        if (Buffer.compare(m, record.certificate) === 0)
            return true;
    }
    return false;
}
function toTlsaRecord(d) {
    return {
        usage: d.usage,
        selector: d.selector,
        matchingType: d.matchingType,
        data: d.certificate.toHex(),
    };
}
export async function runDaneCheck(hostname, opts, dns, tlsT, dnssec) {
    const errors = [];
    const tlsaName = `_443._tcp.${hostname}`;
    const anchors = opts.trustAnchors ?? ROOT_TRUST_ANCHORS;
    // Validate the chain once; a caller-supplied DNSSEC result only saves the first walk.
    let chain = dnssec === undefined ? await validateChain(tlsaName, dns, anchors) : undefined;
    const dnssecResult = dnssec ?? {
        ok: chain.chainValid,
        errors: chain.errors,
        signed: chain.signed,
        chainValid: chain.chainValid,
        chain: chain.chain,
    };
    if (!dnssecResult.chainValid) {
        return {
            ok: false,
            errors: ["DANE requires a valid DNSSEC chain"],
            records: [],
            matched: false,
        };
    }
    chain ??= await validateChain(tlsaName, dns, anchors);
    const recordResult = await verifyRecord("TLSA", tlsaName, chain.finalZoneDnskeys, dns);
    if (recordResult.answers.length === 0) {
        return { ok: false, errors: ["no TLSA records"], records: [], matched: false };
    }
    const tlsaData = recordResult.answers
        .filter((a) => a.type === "TLSA")
        .map((a) => a.data);
    const records = tlsaData.map(toTlsaRecord);
    if (!recordResult.verified) {
        return {
            ok: false,
            errors: [`TLSA RRset failed verification: ${recordResult.error ?? "unknown"}`],
            records,
            matched: false,
        };
    }
    let handshake;
    try {
        handshake = await tlsT.handshake({
            address: hostname,
            servername: hostname,
            timeoutMs: opts.timeoutMs,
        });
    }
    catch (e) {
        return {
            ok: false,
            errors: [`TLS handshake: ${errorMessage(e)}`],
            records,
            matched: false,
        };
    }
    using _ = handshake;
    const matchedRecord = records[tlsaData.findIndex((d) => tlsaMatches(d, handshake.leaf, handshake.chain))];
    if (matchedRecord) {
        return { ok: true, errors, records, matched: true, matchedRecord };
    }
    errors.push("no TLSA record matches the served certificate");
    return { ok: false, errors, records, matched: false };
}
