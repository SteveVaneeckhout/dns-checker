import { Buffer } from "node:buffer";
import { generateKeyPairSync, KeyObject, sign as cryptoSign } from "node:crypto";
import type { Answer, DnskeyData, RrsigData } from "dns-packet";
import { describe, expect, it } from "vitest";
import { computeKeyTag, encodeDnskeyRdata, rrsigSigningInput } from "../../src/dnssec/canonical.ts";
import { verifyRrsig } from "../../src/dnssec/verify.ts";

function publicJwk(key: KeyObject): Record<string, string> {
  return key.export({ format: "jwk" }) as unknown as Record<string, string>;
}

function b64urlDecode(s: string): Buffer {
  const pad = (4 - (s.length % 4)) % 4;
  return Buffer.from(s + "=".repeat(pad), "base64url");
}

function fixedRrset(): Answer[] {
  return [{ name: "example.test.", type: "A", data: "192.0.2.1" }];
}

function makeRrsigHeader(
  typeCovered: "A",
  algorithm: number,
  keyTag: number,
  signersName: string,
): RrsigData {
  return {
    typeCovered,
    algorithm,
    labels: 2,
    originalTTL: 3600,
    expiration: 0x70000000,
    inception: 0x60000000,
    keyTag,
    signersName,
    signature: Buffer.alloc(0),
  };
}

function signRrset(
  rrset: Answer[],
  header: RrsigData,
  privKey: KeyObject,
  signAlg: string | null,
  ecRaw: boolean,
): RrsigData {
  const data = rrsigSigningInput(header, rrset);
  let sig: Buffer;
  if (ecRaw) {
    sig = cryptoSign(signAlg, data, { key: privKey, dsaEncoding: "ieee-p1363" }) as Buffer;
  } else {
    sig = cryptoSign(signAlg, data, privKey) as Buffer;
  }
  return { ...header, signature: sig };
}

describe("verifyRrsig with synthetic keys", () => {
  it("verifies Ed25519 (algorithm 15)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubBytes = b64urlDecode(publicJwk(publicKey)["x"] ?? "");
    const dnskey: DnskeyData = { flags: 257, algorithm: 15, key: pubBytes };
    const keyTag = computeKeyTag(dnskey);
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 15, keyTag, "example.test.");
    const rrsig = signRrset(rrset, header, privateKey, null, false);
    expect(verifyRrsig(rrsig, rrset, [dnskey])).toBe(true);
  });

  it("verifies ECDSA P-256 (algorithm 13)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicJwk(publicKey);
    const pubBytes = Buffer.concat([b64urlDecode(jwk["x"] ?? ""), b64urlDecode(jwk["y"] ?? "")]);
    const dnskey: DnskeyData = { flags: 257, algorithm: 13, key: pubBytes };
    const keyTag = computeKeyTag(dnskey);
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 13, keyTag, "example.test.");
    const rrsig = signRrset(rrset, header, privateKey, "sha256", true);
    expect(verifyRrsig(rrsig, rrset, [dnskey])).toBe(true);
  });

  it("verifies ECDSA P-384 (algorithm 14)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const jwk = publicJwk(publicKey);
    const pubBytes = Buffer.concat([b64urlDecode(jwk["x"] ?? ""), b64urlDecode(jwk["y"] ?? "")]);
    const dnskey: DnskeyData = { flags: 257, algorithm: 14, key: pubBytes };
    const keyTag = computeKeyTag(dnskey);
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 14, keyTag, "example.test.");
    const rrsig = signRrset(rrset, header, privateKey, "sha384", true);
    expect(verifyRrsig(rrsig, rrset, [dnskey])).toBe(true);
  });

  it("verifies RSA/SHA-256 (algorithm 8)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicJwk(publicKey);
    const modulus = b64urlDecode(jwk["n"] ?? "");
    const exponent = b64urlDecode(jwk["e"] ?? "");
    const expLen = exponent.length;
    const dnskeyKey =
      expLen < 256
        ? Buffer.concat([Buffer.from([expLen]), exponent, modulus])
        : Buffer.concat([Buffer.from([0, (expLen >> 8) & 0xff, expLen & 0xff]), exponent, modulus]);
    const dnskey: DnskeyData = { flags: 257, algorithm: 8, key: dnskeyKey };
    const keyTag = computeKeyTag(dnskey);
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 8, keyTag, "example.test.");
    const rrsig = signRrset(rrset, header, privateKey, "RSA-SHA256", false);
    expect(verifyRrsig(rrsig, rrset, [dnskey])).toBe(true);
  });

  it("verifies RSA/SHA-512 (algorithm 10) with long exponent path", () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });
    const jwk = publicJwk(publicKey);
    const modulus = b64urlDecode(jwk["n"] ?? "");
    const exponent = b64urlDecode(jwk["e"] ?? "");
    const expLen = exponent.length;
    const longForm = Buffer.concat([Buffer.from([0, 0, expLen]), exponent, modulus]);
    const dnskey: DnskeyData = { flags: 257, algorithm: 10, key: longForm };
    const keyTag = computeKeyTag(dnskey);
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 10, keyTag, "example.test.");
    const rrsig = signRrset(rrset, header, privateKey, "RSA-SHA512", false);
    expect(verifyRrsig(rrsig, rrset, [dnskey])).toBe(true);
  });

  it("rejects when signature is invalid", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubBytes = b64urlDecode(publicJwk(publicKey)["x"] ?? "");
    const dnskey: DnskeyData = { flags: 257, algorithm: 15, key: pubBytes };
    const keyTag = computeKeyTag(dnskey);
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 15, keyTag, "example.test.");
    const rrsig = signRrset(rrset, header, privateKey, null, false);
    const tampered: RrsigData = { ...rrsig, signature: Buffer.alloc(rrsig.signature.length) };
    expect(verifyRrsig(tampered, rrset, [dnskey])).toBe(false);
  });

  it("returns false when no DNSKEY matches", () => {
    const dnskey: DnskeyData = { flags: 257, algorithm: 8, key: Buffer.alloc(4) };
    const rrset = fixedRrset();
    const header = makeRrsigHeader("A", 15, 0, "example.test.");
    expect(verifyRrsig({ ...header, signature: Buffer.alloc(64) }, rrset, [dnskey])).toBe(false);
  });

  it("returns false when algorithm is unsupported (caught internally)", () => {
    const dnskey: DnskeyData = { flags: 257, algorithm: 5, key: Buffer.alloc(4) };
    const rrset = fixedRrset();
    const tag = computeKeyTag(dnskey);
    const header = {
      ...makeRrsigHeader("A", 5, tag, "example.test."),
      signature: Buffer.alloc(64),
    };
    expect(verifyRrsig(header, rrset, [dnskey])).toBe(false);
  });

  it("returns false when ECDSA key is wrong size", () => {
    const dnskey: DnskeyData = { flags: 257, algorithm: 13, key: Buffer.alloc(20) };
    const rrset = fixedRrset();
    const tag = computeKeyTag(dnskey);
    const header = {
      ...makeRrsigHeader("A", 13, tag, "example.test."),
      signature: Buffer.alloc(64),
    };
    expect(verifyRrsig(header, rrset, [dnskey])).toBe(false);
  });

  it("returns false when RSA DNSKEY is malformed", () => {
    const tag = computeKeyTag({ flags: 257, algorithm: 8, key: Buffer.from([0]) });
    const dnskey: DnskeyData = { flags: 257, algorithm: 8, key: Buffer.from([0]) };
    const rrset = fixedRrset();
    const header = {
      ...makeRrsigHeader("A", 8, tag, "example.test."),
      signature: Buffer.alloc(64),
    };
    expect(verifyRrsig(header, rrset, [dnskey])).toBe(false);
  });

  it("returns false when Ed25519 DNSKEY is wrong size", () => {
    const dnskey: DnskeyData = { flags: 257, algorithm: 15, key: Buffer.alloc(10) };
    const rrset = fixedRrset();
    const tag = computeKeyTag(dnskey);
    const header = {
      ...makeRrsigHeader("A", 15, tag, "example.test."),
      signature: Buffer.alloc(64),
    };
    expect(verifyRrsig(header, rrset, [dnskey])).toBe(false);
  });
});
