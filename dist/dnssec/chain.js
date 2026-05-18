import { Buffer } from "node:buffer";
import { computeDsDigest, computeKeyTag } from "./canonical.js";
import { ROOT_TRUST_ANCHORS } from "./rootKeys.js";
import { verifyRrsig } from "./verify.js";
function pickRrset(packet, type, name) {
    const all = packet.answers ?? [];
    const lname = name.toLowerCase().replace(/\.$/, "");
    const matches = all.filter((a) => a.type === type && a.name.toLowerCase().replace(/\.$/, "") === lname);
    const rrsig = all.find((a) => a.type === "RRSIG" &&
        a.name.toLowerCase().replace(/\.$/, "") === lname &&
        a.data.typeCovered === type);
    return { rrset: matches, rrsig: rrsig?.data };
}
function dsMatches(ds, ownerName, dnskey) {
    if (computeKeyTag(dnskey) !== ds.keyTag)
        return false;
    if (dnskey.algorithm !== ds.algorithm)
        return false;
    let digest;
    try {
        digest = computeDsDigest(ownerName, dnskey, ds.digestType);
    }
    catch {
        return false;
    }
    return Buffer.compare(digest, ds.digest) === 0;
}
function findZoneCuts(host) {
    const labels = host.split(".").filter((l) => l.length > 0);
    const zones = ["."];
    for (let i = 1; i <= labels.length; i++) {
        zones.push(labels.slice(-i).join("."));
    }
    return zones;
}
async function fetchDnskeys(dns, zone) {
    const queryName = zone === "." ? "." : zone;
    const packet = await dns.query({ type: "DNSKEY", name: queryName, dnssec: true });
    return pickRrset(packet, "DNSKEY", queryName);
}
async function fetchDs(dns, zone) {
    const packet = await dns.query({ type: "DS", name: zone, dnssec: true });
    return pickRrset(packet, "DS", zone);
}
const MAX_CNAME_DEPTH = 8;
async function validateLeaf(host, parentKeys, dns, anchors, errors, depth) {
    if (depth >= MAX_CNAME_DEPTH) {
        errors.push(`CNAME chain depth limit (${MAX_CNAME_DEPTH}) exceeded at ${host}`);
        return false;
    }
    let packet;
    try {
        packet = await dns.query({ type: "A", name: host, dnssec: true });
    }
    catch (e) {
        errors.push(`A query for ${host}: ${e.message}`);
        return false;
    }
    const cname = pickRrset(packet, "CNAME", host);
    if (cname.rrset.length > 0) {
        if (!cname.rrsig) {
            errors.push(`CNAME ${host} is unsigned`);
            return false;
        }
        const sigOk = verifyRrsig(cname.rrsig, cname.rrset, parentKeys);
        if (!sigOk) {
            errors.push(`CNAME ${host} RRSIG did not verify`);
            return false;
        }
        const first = cname.rrset[0];
        const rawTarget = first?.data;
        if (typeof rawTarget !== "string") {
            errors.push(`CNAME ${host}: unparseable target`);
            return false;
        }
        const target = rawTarget.toLowerCase().replace(/\.$/, "");
        const targetResult = await validateChain(target, dns, anchors, depth + 1);
        if (!targetResult.signed) {
            for (const e of targetResult.errors)
                errors.push(`(resolving ${target}) ${e}`);
            errors.push(`CNAME ${host} -> ${target}: target is insecure (not in a signed zone)`);
            return false;
        }
        return true;
    }
    const a = pickRrset(packet, "A", host);
    if (a.rrset.length > 0) {
        if (!a.rrsig) {
            errors.push(`A ${host} is unsigned`);
            return false;
        }
        const sigOk = verifyRrsig(a.rrsig, a.rrset, parentKeys);
        if (!sigOk) {
            errors.push(`A ${host} RRSIG did not verify`);
            return false;
        }
        return true;
    }
    return true;
}
export async function validateChain(host, dns, anchors = ROOT_TRUST_ANCHORS, depth = 0) {
    const result = {
        signed: false,
        chainValid: false,
        chain: [],
        errors: [],
        finalZoneDnskeys: [],
        finalZone: ".",
    };
    let rootKeys;
    try {
        const root = await fetchDnskeys(dns, ".");
        if (root.rrset.length === 0 || !root.rrsig) {
            result.errors.push("root DNSKEY RRset missing or unsigned");
            return result;
        }
        const rootKeyData = root.rrset.map((a) => a.data);
        const rootKsk = rootKeyData.find((k) => anchors.some((ta) => computeKeyTag(k) === ta.keyTag &&
            k.algorithm === ta.algorithm &&
            Buffer.compare(computeDsDigest(".", k, ta.digestType), Buffer.from(ta.digestHex, "hex")) === 0));
        if (!rootKsk) {
            result.errors.push("no root DNSKEY matches IANA trust anchor");
            return result;
        }
        const rootSigOk = verifyRrsig(root.rrsig, root.rrset.map((a) => ({ ...a, data: a.data })), rootKeyData);
        if (!rootSigOk) {
            result.errors.push("root DNSKEY RRSIG did not verify");
            return result;
        }
        rootKeys = rootKeyData;
        result.chain.push({ zone: ".", dsVerified: true, keysVerified: true });
    }
    catch (e) {
        result.errors.push(`root DNSKEY: ${e.message}`);
        return result;
    }
    const zones = findZoneCuts(host).filter((z) => z !== ".");
    let parentKeys = rootKeys;
    let parentZone = ".";
    let lastValidatedZone = ".";
    for (const child of zones) {
        let ds;
        try {
            ds = await fetchDs(dns, child);
        }
        catch (e) {
            result.errors.push(`DS query for ${child}: ${e.message}`);
            break;
        }
        if (ds.rrset.length === 0) {
            // no DS at this label — not a zone cut; keep going (parent stays the same)
            continue;
        }
        if (!ds.rrsig) {
            result.errors.push(`DS ${child} is unsigned`);
            break;
        }
        const dsOk = verifyRrsig(ds.rrsig, ds.rrset, parentKeys);
        if (!dsOk) {
            result.errors.push(`DS ${child} RRSIG invalid under ${parentZone}`);
            break;
        }
        let dnskey;
        try {
            dnskey = await fetchDnskeys(dns, child);
        }
        catch (e) {
            result.errors.push(`DNSKEY query for ${child}: ${e.message}`);
            break;
        }
        if (dnskey.rrset.length === 0 || !dnskey.rrsig) {
            result.errors.push(`DNSKEY for ${child} missing or unsigned`);
            break;
        }
        const childKeyData = dnskey.rrset.map((a) => a.data);
        const matched = childKeyData.some((k) => ds.rrset.some((d) => dsMatches(d.data, child, k)));
        if (!matched) {
            result.errors.push(`no DNSKEY for ${child} matches DS from parent`);
            break;
        }
        const keysSig = verifyRrsig(dnskey.rrsig, dnskey.rrset, childKeyData);
        if (!keysSig) {
            result.errors.push(`DNSKEY ${child} RRSIG invalid`);
            break;
        }
        result.chain.push({ zone: child, dsVerified: true, keysVerified: true });
        parentKeys = childKeyData;
        parentZone = child;
        lastValidatedZone = child;
    }
    let leafSecure = true;
    if (result.errors.length === 0 && result.chain.length > 1) {
        leafSecure = await validateLeaf(host, parentKeys, dns, anchors, result.errors, depth);
    }
    result.signed = result.chain.length > 1 && leafSecure;
    result.chainValid = result.errors.length === 0 && result.signed;
    result.finalZoneDnskeys = parentKeys;
    result.finalZone = lastValidatedZone;
    return result;
}
export async function verifyRecord(type, name, dnskeys, dns) {
    try {
        const packet = await dns.query({ type, name, dnssec: true });
        const got = pickRrset(packet, type, name);
        if (got.rrset.length === 0)
            return { verified: false, answers: [], error: "no records" };
        if (!got.rrsig)
            return { verified: false, answers: got.rrset, error: "no RRSIG" };
        const ok = verifyRrsig(got.rrsig, got.rrset, dnskeys);
        return { verified: ok, answers: got.rrset };
    }
    catch (e) {
        return { verified: false, answers: [], error: e.message };
    }
}
