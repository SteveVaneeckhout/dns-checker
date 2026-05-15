import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { validateChain, verifyRecord } from "../dnssec/chain.js";
import { ROOT_TRUST_ANCHORS } from "../dnssec/rootKeys.js";
function selectorData(cert, selector) {
  if (selector === 0) {
    return cert.raw;
  }
  if (selector === 1) {
    return cert.pubkey;
  }
  return undefined;
}
function matchData(data, matchingType) {
  if (matchingType === 0) return data;
  if (matchingType === 1) return createHash("sha256").update(data).digest();
  if (matchingType === 2) return createHash("sha512").update(data).digest();
  return undefined;
}
function tlsaCertsForUsage(usage, leaf, chain) {
  if (usage === 1 || usage === 3) return [leaf];
  if (usage === 0 || usage === 2) return chain.slice(1);
  return [];
}
export function tlsaMatches(record, leaf, chain) {
  const certs = tlsaCertsForUsage(record.usage, leaf, chain);
  for (const cert of certs) {
    const sel = selectorData(cert, record.selector);
    if (!sel) continue;
    const m = matchData(sel, record.matchingType);
    if (!m) continue;
    if (Buffer.compare(m, record.certificate) === 0) return true;
  }
  return false;
}
export async function runDaneCheck(hostname, opts, dns, tlsT, dnssec) {
  const errors = [];
  const tlsaName = `_443._tcp.${hostname}`;
  const anchors = opts.trustAnchors ?? ROOT_TRUST_ANCHORS;
  let dnssecResult = dnssec;
  if (!dnssecResult) {
    const chain = await validateChain(tlsaName, dns, anchors);
    dnssecResult = {
      ok: chain.chainValid,
      errors: chain.errors,
      signed: chain.signed,
      chainValid: chain.chainValid,
      chain: chain.chain,
    };
  }
  if (!dnssecResult.chainValid) {
    return {
      ok: false,
      errors: ["DANE requires a valid DNSSEC chain"],
      records: [],
      matched: false,
    };
  }
  const finalChain = await validateChain(tlsaName, dns, anchors);
  const recordResult = await verifyRecord("TLSA", tlsaName, finalChain.finalZoneDnskeys, dns);
  if (recordResult.answers.length === 0) {
    return { ok: false, errors: ["no TLSA records"], records: [], matched: false };
  }
  if (!recordResult.verified) {
    return {
      ok: false,
      errors: [`TLSA RRset failed verification: ${recordResult.error ?? "unknown"}`],
      records: recordResult.answers
        .filter((a) => a.type === "TLSA")
        .map((a) => {
          const d = a.data;
          return {
            usage: d.usage,
            selector: d.selector,
            matchingType: d.matchingType,
            data: d.certificate.toString("hex"),
          };
        }),
      matched: false,
    };
  }
  const records = recordResult.answers
    .filter((a) => a.type === "TLSA")
    .map((a) => {
      const d = a.data;
      return {
        usage: d.usage,
        selector: d.selector,
        matchingType: d.matchingType,
        data: d.certificate.toString("hex"),
      };
    });
  let handshake;
  try {
    handshake = await tlsT.handshake({
      address: hostname,
      servername: hostname,
      timeoutMs: opts.timeoutMs,
    });
  } catch (e) {
    return {
      ok: false,
      errors: [`TLS handshake: ${e.message}`],
      records,
      matched: false,
    };
  }
  handshake.socket.destroy();
  let matchedRecord;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (!r) continue;
    const rawTlsa = recordResult.answers.filter((a) => a.type === "TLSA")[i]?.data;
    if (!rawTlsa) continue;
    if (tlsaMatches(rawTlsa, handshake.leaf, handshake.chain)) {
      matchedRecord = r;
      break;
    }
  }
  if (matchedRecord) {
    return { ok: true, errors, records, matched: true, matchedRecord };
  }
  errors.push("no TLSA record matches the served certificate");
  return { ok: false, errors, records, matched: false };
}
