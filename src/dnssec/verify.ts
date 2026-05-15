import { Buffer } from "node:buffer";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { Answer, DnskeyData, RrsigData } from "dns-packet";
import { computeKeyTag, rrsigSigningInput } from "./canonical.js";

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function parseRsaKey(key: Buffer): { modulus: Buffer; exponent: Buffer } {
  if (key.length < 1) throw new Error("RSA DNSKEY too short");
  let offset = 0;
  let expLen = key[0] ?? 0;
  offset = 1;
  if (expLen === 0) {
    if (key.length < 3) throw new Error("RSA DNSKEY too short");
    expLen = key.readUInt16BE(1);
    offset = 3;
  }
  if (key.length < offset + expLen + 1) throw new Error("RSA DNSKEY truncated");
  const exponent = key.subarray(offset, offset + expLen);
  const modulus = key.subarray(offset + expLen);
  return { modulus, exponent };
}

function makeRsaPublicKey(key: Buffer) {
  const { modulus, exponent } = parseRsaKey(key);
  return createPublicKey({
    key: { kty: "RSA", n: b64url(modulus), e: b64url(exponent) },
    format: "jwk",
  });
}

function makeEcdsaPublicKey(key: Buffer, curve: "P-256" | "P-384") {
  const expected = curve === "P-256" ? 64 : 96;
  if (key.length !== expected) throw new Error(`ECDSA ${curve} DNSKEY wrong size`);
  const half = expected / 2;
  const x = b64url(key.subarray(0, half));
  const y = b64url(key.subarray(half));
  return createPublicKey({
    key: { kty: "EC", crv: curve, x, y },
    format: "jwk",
  });
}

function makeEd25519PublicKey(key: Buffer) {
  if (key.length !== 32) throw new Error("Ed25519 DNSKEY wrong size");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: b64url(key) },
    format: "jwk",
  });
}

export function verifyRrsig(rrsig: RrsigData, rrset: Answer[], dnskeys: DnskeyData[]): boolean {
  const candidates = dnskeys.filter(
    (k) => computeKeyTag(k) === rrsig.keyTag && k.algorithm === rrsig.algorithm,
  );
  if (candidates.length === 0) return false;
  const data = rrsigSigningInput(rrsig, rrset);
  for (const key of candidates) {
    try {
      if (verifyOne(rrsig, data, key)) return true;
    } catch {
      // try the next candidate
    }
  }
  return false;
}

function verifyOne(rrsig: RrsigData, data: Buffer, dnskey: DnskeyData): boolean {
  switch (rrsig.algorithm) {
    case 8:
      return cryptoVerify("RSA-SHA256", data, makeRsaPublicKey(dnskey.key), rrsig.signature);
    case 10:
      return cryptoVerify("RSA-SHA512", data, makeRsaPublicKey(dnskey.key), rrsig.signature);
    case 13:
      return cryptoVerify(
        "sha256",
        data,
        { key: makeEcdsaPublicKey(dnskey.key, "P-256"), dsaEncoding: "ieee-p1363" },
        rrsig.signature,
      );
    case 14:
      return cryptoVerify(
        "sha384",
        data,
        { key: makeEcdsaPublicKey(dnskey.key, "P-384"), dsaEncoding: "ieee-p1363" },
        rrsig.signature,
      );
    case 15:
      return cryptoVerify(null, data, makeEd25519PublicKey(dnskey.key), rrsig.signature);
    default:
      throw new Error(`unsupported DNSSEC algorithm: ${rrsig.algorithm}`);
  }
}
