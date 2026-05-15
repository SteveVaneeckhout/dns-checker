import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { TlsaData } from "dns-packet";
import { runDaneCheck, tlsaMatches } from "../../src/checks/dane.ts";
import { resolveOptions } from "../../src/options.ts";
import {
  buildPacket,
  makeDsForChild,
  makeZone,
  makeTrustAnchorFor,
  signRrset,
} from "../helpers/dnssecFixtures.ts";
import {
  fakeCert,
  fakeHandshake,
  mockDns,
  mockTls,
  packetWith,
} from "../helpers/mockTransports.ts";

const opts = resolveOptions("host.test");

function sha256(b: Buffer) {
  return createHash("sha256").update(b).digest();
}

describe("tlsaMatches", () => {
  it("matches leaf cert SPKI SHA-256 (3 1 1)", () => {
    const pubkey = Buffer.from("0102030405", "hex");
    const cert = fakeCert({ pubkey });
    const data: TlsaData = {
      usage: 3,
      selector: 1,
      matchingType: 1,
      certificate: sha256(pubkey),
    };
    expect(tlsaMatches(data, cert, [cert])).toBe(true);
  });
  it("matches leaf cert full DER exact (3 0 0)", () => {
    const raw = Buffer.from("ababab", "hex");
    const cert = fakeCert({ raw });
    const data: TlsaData = { usage: 3, selector: 0, matchingType: 0, certificate: raw };
    expect(tlsaMatches(data, cert, [cert])).toBe(true);
  });
  it("matches CA SHA-512 (2 0 2)", () => {
    const caRaw = Buffer.from("cafefe", "hex");
    const ca = fakeCert({ raw: caRaw });
    const leaf = fakeCert();
    const data: TlsaData = {
      usage: 2,
      selector: 0,
      matchingType: 2,
      certificate: createHash("sha512").update(caRaw).digest(),
    };
    expect(tlsaMatches(data, leaf, [leaf, ca])).toBe(true);
  });
  it("returns false on unsupported selector", () => {
    expect(
      tlsaMatches(
        { usage: 3, selector: 99, matchingType: 1, certificate: Buffer.alloc(0) },
        fakeCert(),
        [fakeCert()],
      ),
    ).toBe(false);
  });
  it("returns false on unsupported matching type", () => {
    expect(
      tlsaMatches(
        { usage: 3, selector: 0, matchingType: 99, certificate: Buffer.alloc(0) },
        fakeCert(),
        [fakeCert()],
      ),
    ).toBe(false);
  });
  it("returns false on unsupported usage", () => {
    expect(
      tlsaMatches(
        { usage: 99, selector: 0, matchingType: 0, certificate: Buffer.alloc(0) },
        fakeCert(),
        [fakeCert()],
      ),
    ).toBe(false);
  });
  it("returns false when no match", () => {
    expect(
      tlsaMatches(
        { usage: 3, selector: 1, matchingType: 1, certificate: Buffer.alloc(32) },
        fakeCert({ pubkey: Buffer.from([1]) }),
        [fakeCert({ pubkey: Buffer.from([1]) })],
      ),
    ).toBe(false);
  });
});

describe("runDaneCheck", () => {
  it("fails when supplied DNSSEC result is invalid", async () => {
    const dns = mockDns(() => packetWith([]));
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runDaneCheck("host.test", opts, dns, tls, {
      ok: false,
      errors: ["bad"],
      signed: false,
      chainValid: false,
      chain: [],
    });
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/DANE requires/);
  });

  it("falls back to validating DNSSEC itself when not supplied (and fails)", async () => {
    const dns = mockDns(() => packetWith([]));
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runDaneCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(false);
  });
});

describe("runDaneCheck with a signed zone fixture", () => {
  function buildEnv(tlsaRecords: TlsaData[], opts: { tamperTlsaSig?: boolean } = {}) {
    const root = makeZone(".");
    const tld = makeZone("test");
    const apex = makeZone("host.test");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "test", tld);
    const dsApex = makeDsForChild(tld, "host.test", apex);
    const tlsaName = "_443._tcp.host.test";
    const tlsaAnswers = tlsaRecords.map((d) => ({
      name: tlsaName,
      type: "TLSA" as const,
      data: d,
    }));
    const tlsaSigner = opts.tamperTlsaSig ? makeZone("host.test") : apex;
    const tlsaSigs =
      tlsaAnswers.length > 0 ? [signRrset(tlsaAnswers, "TLSA", tlsaSigner, tlsaName)] : [];
    const dns = mockDns((q) => {
      if (q.type === "DNSKEY" && q.name === ".")
        return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
      if (q.type === "DNSKEY" && q.name === "test")
        return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
      if (q.type === "DNSKEY" && q.name === "host.test")
        return buildPacket(apex.dnskeyAnswers, [apex.dnskeySig]);
      if (q.type === "DS" && q.name === "test") return buildPacket(dsTld.records, [dsTld.rrsig]);
      if (q.type === "DS" && q.name === "host.test")
        return buildPacket(dsApex.records, [dsApex.rrsig]);
      if (q.type === "DS") return buildPacket([], []);
      if (q.type === "TLSA" && q.name === tlsaName) return buildPacket(tlsaAnswers, tlsaSigs);
      return buildPacket([], []);
    });
    const localOpts = { ...opts, trustAnchors: [anchor] };
    return { dns, localOpts };
  }

  const validDnssec = {
    ok: true,
    errors: [],
    signed: true,
    chainValid: true,
    chain: [],
  };

  it("returns ok when a TLSA record matches the served cert", async () => {
    const pubkey = Buffer.from("11223344", "hex");
    const cert = fakeCert({ pubkey });
    const tlsaRecord: TlsaData = {
      usage: 3,
      selector: 1,
      matchingType: 1,
      certificate: sha256(pubkey),
    };
    const { dns, localOpts } = buildEnv([tlsaRecord]);
    const tls = mockTls(() => fakeHandshake(cert));
    const r = await runDaneCheck("host.test", localOpts, dns, tls, validDnssec);
    expect(r.ok).toBe(true);
    expect(r.matched).toBe(true);
    expect(r.matchedRecord?.selector).toBe(1);
  });

  it("returns not ok when no TLSA record matches", async () => {
    const tlsaRecord: TlsaData = {
      usage: 3,
      selector: 1,
      matchingType: 1,
      certificate: Buffer.alloc(32),
    };
    const { dns, localOpts } = buildEnv([tlsaRecord]);
    const tls = mockTls(() => fakeHandshake(fakeCert({ pubkey: Buffer.from([1, 2, 3]) })));
    const r = await runDaneCheck("host.test", localOpts, dns, tls, validDnssec);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/no TLSA record matches/);
  });

  it("returns no TLSA when zone has none", async () => {
    const { dns, localOpts } = buildEnv([]);
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runDaneCheck("host.test", localOpts, dns, tls, validDnssec);
    expect(r.ok).toBe(false);
    expect(r.errors).toContain("no TLSA records");
  });

  it("returns not ok when the TLSA RRset RRSIG fails to verify", async () => {
    const tlsaRecord: TlsaData = {
      usage: 3,
      selector: 1,
      matchingType: 1,
      certificate: Buffer.alloc(32),
    };
    const { dns, localOpts } = buildEnv([tlsaRecord], { tamperTlsaSig: true });
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runDaneCheck("host.test", localOpts, dns, tls, validDnssec);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/TLSA RRset failed verification/);
    expect(r.records.length).toBe(1);
    expect(r.records[0]?.selector).toBe(1);
    expect(r.matched).toBe(false);
  });

  it("captures TLS handshake error", async () => {
    const tlsaRecord: TlsaData = {
      usage: 3,
      selector: 1,
      matchingType: 1,
      certificate: Buffer.alloc(32),
    };
    const { dns, localOpts } = buildEnv([tlsaRecord]);
    const tls = mockTls(() => {
      throw new Error("tls boom");
    });
    const r = await runDaneCheck("host.test", localOpts, dns, tls, validDnssec);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/tls boom/);
  });
});
