import { certIssuerString, certSubjectCN } from "../net/tls.js";
import { errorMessage } from "../util/errors.js";
/**
 * Certificate authorities: the CAA issuer-domain-names each one publishes (CCADB "CAA
 * identifiers"), and substrings of the certificate issuer that identify its certificates. A CA
 * honours all of its identifiers for every certificate it issues, including the ones it issues
 * under a brand or reseller name (ZeroSSL, GoGetSSL, … for Sectigo; GeoTrust, RapidSSL, … for
 * DigiCert).
 */
const CERTIFICATE_AUTHORITIES = [
    { ids: ["letsencrypt.org"], issuers: ["Let's Encrypt"] },
    { ids: ["pki.goog", "google.com"], issuers: ["Google Trust Services", "GTS"] },
    {
        ids: ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"],
        issuers: ["Amazon"],
    },
    {
        ids: [
            "digicert.com",
            "www.digicert.com",
            "digicert.ne.jp",
            "digitalcertvalidation.com",
            "geotrust.com",
            "rapidssl.com",
            "thawte.com",
            "symantec.com",
            "quovadisglobal.com",
        ],
        issuers: ["DigiCert", "GeoTrust", "RapidSSL", "Thawte", "Symantec", "QuoVadis"],
    },
    {
        ids: ["sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"],
        issuers: [
            "Sectigo",
            "Comodo",
            "USERTrust",
            "ZeroSSL",
            "GoGetSSL",
            "Gandi",
            "InCommon",
            "cPanel",
        ],
    },
    { ids: ["globalsign.com"], issuers: ["GlobalSign"] },
    { ids: ["godaddy.com", "starfieldtech.com"], issuers: ["GoDaddy", "Go Daddy", "Starfield"] },
    { ids: ["buypass.com", "buypass.no"], issuers: ["Buypass"] },
    { ids: ["entrust.net", "affirmtrust.com"], issuers: ["Entrust", "AffirmTrust"] },
    { ids: ["ssl.com"], issuers: ["SSL.com", "SSL Corp"] },
    { ids: ["certum.pl"], issuers: ["Certum", "Asseco", "Unizeto"] },
    { ids: ["harica.gr"], issuers: ["HARICA", "Hellenic Academic"] },
    { ids: ["certainly.com"], issuers: ["Certainly"] },
    { ids: ["swisssign.com"], issuers: ["SwissSign"] },
    { ids: ["microsoft.com"], issuers: ["Microsoft"] },
    { ids: ["identrust.com"], issuers: ["IdenTrust"] },
    { ids: ["emsign.com"], issuers: ["eMudhra", "emSign"] },
    { ids: ["telesec.de"], issuers: ["T-Systems", "TeleSec", "Telekom Security"] },
    { ids: ["d-trust.net"], issuers: ["D-Trust"] },
    { ids: ["certsign.ro"], issuers: ["certSIGN"] },
    { ids: ["actalis.it"], issuers: ["Actalis"] },
    { ids: ["certigna.fr"], issuers: ["Certigna", "Dhimyotis"] },
    { ids: ["trustwave.com", "securetrust.com"], issuers: ["Trustwave", "SecureTrust"] },
    { ids: ["twca.com.tw"], issuers: ["TAIWAN-CA", "TWCA"] },
    { ids: ["pki.apple.com"], issuers: ["Apple"] },
    { ids: ["e-szigno.hu"], issuers: ["Microsec", "e-Szigno"] },
    { ids: ["infocert.it"], issuers: ["InfoCert"] },
    { ids: ["cybertrust.ne.jp"], issuers: ["Cybertrust Japan"] },
    { ids: ["telia.com"], issuers: ["Telia"] },
    { ids: ["trustasia.com"], issuers: ["TrustAsia"] },
    { ids: ["jprs.jp"], issuers: ["JPRS", "Japan Registry Services"] },
    { ids: ["secomtrust.net"], issuers: ["SECOM"] },
    { ids: ["fnmt.es"], issuers: ["FNMT"] },
    { ids: ["firmaprofesional.com"], issuers: ["Firmaprofesional"] },
];
// A Map, not an object literal: CAA tags come from DNS, and names like "constructor"
// must not resolve to inherited Object.prototype members.
const CA_TAG_MAP = new Map(CERTIFICATE_AUTHORITIES.flatMap(({ ids, issuers }) => ids.map((id) => [id, issuers])));
function parentZone(name) {
    const idx = name.indexOf(".");
    if (idx === -1)
        return undefined;
    return name.slice(idx + 1);
}
async function fetchCaa(dns, zone) {
    const packet = await dns.query({ type: "CAA", name: zone });
    const records = (packet.answers ?? [])
        .filter((a) => a.type === "CAA")
        .map((a) => a.data);
    return { zone, records };
}
export async function findCaaRecords(dns, hostname) {
    let cur = hostname;
    while (cur) {
        try {
            const r = await fetchCaa(dns, cur);
            if (r.records.length > 0)
                return r;
        }
        catch {
            // continue walking up
        }
        cur = parentZone(cur);
    }
    return { zone: hostname, records: [] };
}
export function issuerMatchesTag(issuer, tag) {
    const cleaned = tag.trim().split(";")[0]?.trim().toLowerCase() ?? "";
    if (cleaned === "")
        return { matched: false, known: true };
    const aliases = CA_TAG_MAP.get(cleaned);
    if (!aliases)
        return { matched: false, known: false };
    const lower = issuer.toLowerCase();
    for (const alias of aliases) {
        if (lower.includes(alias.toLowerCase()))
            return { matched: true, known: true };
    }
    return { matched: false, known: true };
}
export async function runCaaCheck(hostname, opts, dns, tls) {
    const errors = [];
    let caa;
    try {
        caa = await findCaaRecords(dns, hostname);
    }
    catch (e) {
        return {
            ok: false,
            errors: [`CAA lookup: ${errorMessage(e)}`],
            records: [],
        };
    }
    const recordList = caa.records.map((r) => ({
        zone: caa.zone,
        flags: r.flags ?? (r.issuerCritical ? 128 : 0),
        tag: r.tag,
        value: r.value,
    }));
    if (recordList.length === 0) {
        return { ok: true, errors: [], records: [] };
    }
    let issuer = "";
    let isWild = false;
    try {
        using r = await tls.handshake({
            address: hostname,
            servername: hostname,
            timeoutMs: opts.timeoutMs,
        });
        issuer = certIssuerString(r.leaf);
        const subj = certSubjectCN(r.leaf);
        isWild = subj.startsWith("*.");
    }
    catch (e) {
        errors.push(`TLS handshake: ${errorMessage(e)}`);
        return { ok: false, errors, records: recordList };
    }
    // RFC 8659 §4.1: tags match case-insensitively. §4.3: for a wildcard certificate, issuewild
    // properties, when there are any, replace the issue properties entirely.
    const byTag = (tag) => recordList.filter((r) => r.tag.toLowerCase() === tag);
    const issuewild = isWild ? byTag("issuewild") : [];
    const relevant = issuewild.length > 0 ? issuewild : byTag("issue");
    if (relevant.length === 0) {
        // §4.2: without an applicable issue property, CAA does not restrict issuance.
        return { ok: true, errors, records: recordList, certIssuer: issuer };
    }
    for (const rec of relevant) {
        const m = issuerMatchesTag(issuer, rec.value);
        if (!m.known) {
            errors.push(`unknown CA tag: ${rec.value.split(";")[0]}`);
            continue;
        }
        if (m.matched) {
            const matchedTag = rec.value.split(";")[0]?.trim();
            return {
                ok: true,
                errors,
                records: recordList,
                certIssuer: issuer,
                ...(matchedTag !== undefined ? { matchedTag } : {}),
            };
        }
    }
    errors.push(`certificate issuer '${issuer}' not permitted by CAA`);
    return { ok: false, errors, records: recordList, certIssuer: issuer };
}
