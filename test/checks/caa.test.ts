import { describe, expect, it } from "vitest";
import { issuerMatchesTag, runCaaCheck } from "../../src/checks/caa.ts";
import { resolveOptions } from "../../src/options.ts";
import {
  fakeCert,
  fakeHandshake,
  mockDns,
  mockTls,
  packetWith,
} from "../helpers/mockTransports.ts";

const opts = resolveOptions("host.test");

describe("issuerMatchesTag", () => {
  it("matches a known CA alias", () => {
    expect(issuerMatchesTag("O=Let's Encrypt, CN=R3", "letsencrypt.org")).toEqual({
      matched: true,
      known: true,
    });
  });
  it("reports unknown CA tag", () => {
    expect(issuerMatchesTag("issuer", "unknownca.example")).toEqual({
      matched: false,
      known: false,
    });
  });
  it("returns matched=false but known when no alias matches", () => {
    expect(issuerMatchesTag("O=DigiCert", "letsencrypt.org")).toEqual({
      matched: false,
      known: true,
    });
  });
  it("returns matched=false when value is empty after parsing", () => {
    expect(issuerMatchesTag("issuer", ";policy=value")).toEqual({ matched: false, known: true });
  });
  it.each([
    ["amazonaws.com", "O=Amazon, CN=Amazon RSA 2048 M04"],
    ["awstrust.com", "O=Amazon, CN=Amazon RSA 2048 M04"],
    ["www.digicert.com", "O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"],
    ["geotrust.com", "O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1"],
    ["digicert.com", "O=DigiCert, Inc., CN=GeoTrust G2 TLS CN RSA4096 SHA256 2022 CA1"],
    ["usertrust.com", "O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV R36"],
    ["trust-provider.com", "O=ZeroSSL GmbH, CN=ZeroSSL ECC DV SSL CA 2"],
    ["sectigo.com", "O=GoGetSSL, CN=GoGetSSL RSA DV SSL CA 2"],
    ["comodo.com", "O=Internet2, CN=InCommon RSA Server CA 2"],
    ["starfieldtech.com", "O=GoDaddy.com, Inc., CN=Go Daddy Secure Certificate Authority - G2"],
    ["harica.gr", "O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1"],
    ["certainly.com", "O=Certainly, CN=Certainly Intermediate R1"],
    ["WWW.DigiCert.com", "O=DigiCert Inc, CN=RapidSSL TLS RSA CA G1"],
  ])("knows the CAA identifier %j and matches its issuer %j", (tag, issuer) => {
    expect(issuerMatchesTag(issuer, tag)).toEqual({ matched: true, known: true });
  });
  it("does not let one CA's identifier match another CA's certificate", () => {
    expect(issuerMatchesTag("O=Amazon, CN=Amazon RSA 2048 M04", "harica.gr")).toEqual({
      matched: false,
      known: true,
    });
    expect(issuerMatchesTag("O=Let's Encrypt, CN=R3", "usertrust.com")).toEqual({
      matched: false,
      known: true,
    });
  });
  it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
    "treats the Object.prototype name %j as an unknown CA tag instead of crashing",
    (tag) => {
      expect(issuerMatchesTag("O=Let's Encrypt, CN=R3", tag)).toEqual({
        matched: false,
        known: false,
      });
    },
  );
});

describe("runCaaCheck", () => {
  it("returns ok when no CAA records exist (RFC permits)", async () => {
    const dns = mockDns(() => packetWith([]));
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(true);
    expect(r.records).toEqual([]);
  });

  it("returns ok when issuer matches CAA issue", async () => {
    const dns = mockDns((q) =>
      q.type === "CAA"
        ? packetWith([
            {
              name: q.name,
              type: "CAA",
              data: { tag: "issue", value: "letsencrypt.org", flags: 0 },
            },
          ])
        : packetWith([]),
    );
    const tls = mockTls(() =>
      fakeHandshake(fakeCert({ issuerO: "Let's Encrypt", issuerCN: "R3", subjectCN: "host.test" })),
    );
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(true);
    expect(r.matchedTag).toBe("letsencrypt.org");
  });

  it("returns not ok when issuer does not match CAA", async () => {
    const dns = mockDns((q) =>
      q.type === "CAA"
        ? packetWith([
            {
              name: q.name,
              type: "CAA",
              data: { tag: "issue", value: "letsencrypt.org" },
            },
          ])
        : packetWith([]),
    );
    const tls = mockTls(() =>
      fakeHandshake(fakeCert({ issuerO: "DigiCert", issuerCN: "DigiCert TLS RSA" })),
    );
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/not permitted/);
  });

  it("reports TLS handshake failure", async () => {
    const dns = mockDns((q) =>
      q.type === "CAA"
        ? packetWith([
            {
              name: q.name,
              type: "CAA",
              data: { tag: "issue", value: "letsencrypt.org" },
            },
          ])
        : packetWith([]),
    );
    const tls = mockTls(() => {
      throw new Error("tls boom");
    });
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/tls boom/);
  });

  it("walks up to parent zones to find CAA", async () => {
    const dns = mockDns((q) => {
      if (q.type !== "CAA") return packetWith([]);
      if (q.name === "host.test") return packetWith([]);
      return packetWith([
        { name: q.name, type: "CAA", data: { tag: "issue", value: "letsencrypt.org" } },
      ]);
    });
    const tls = mockTls(() =>
      fakeHandshake(fakeCert({ issuerO: "Let's Encrypt", issuerCN: "R3" })),
    );
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(true);
    expect(r.records[0]?.zone).toBe("test");
  });

  it("recovers from CAA query exception by walking up", async () => {
    const dns = mockDns((q) => {
      if (q.type !== "CAA") return packetWith([]);
      if (q.name === "host.test") throw new Error("transient");
      return packetWith([
        { name: q.name, type: "CAA", data: { tag: "issue", value: "letsencrypt.org" } },
      ]);
    });
    const tls = mockTls(() =>
      fakeHandshake(fakeCert({ issuerO: "Let's Encrypt", issuerCN: "R3" })),
    );
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(true);
  });

  it("uses issuewild for wildcard subject", async () => {
    const dns = mockDns((q) =>
      q.type === "CAA"
        ? packetWith([
            {
              name: q.name,
              type: "CAA",
              data: { tag: "issuewild", value: "letsencrypt.org" },
            },
          ])
        : packetWith([]),
    );
    const tls = mockTls(() =>
      fakeHandshake(
        fakeCert({
          issuerO: "Let's Encrypt",
          issuerCN: "R3",
          subjectCN: "*.host.test",
        }),
      ),
    );
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(true);
  });

  it("flags unknown CA tag", async () => {
    const dns = mockDns((q) =>
      q.type === "CAA"
        ? packetWith([
            {
              name: q.name,
              type: "CAA",
              data: { tag: "issue", value: "secretca.invalid" },
            },
          ])
        : packetWith([]),
    );
    const tls = mockTls(() => fakeHandshake(fakeCert({ issuerO: "SecretCA", issuerCN: "X" })));
    const r = await runCaaCheck("host.test", opts, dns, tls);
    expect(r.errors.join(" ")).toMatch(/unknown CA tag/);
  });

  describe("RFC 8659 issue/issuewild selection", () => {
    type Rec = { tag: string; value: string; flags?: number };
    const LE = { issuerO: "Let's Encrypt", issuerCN: "R3" };

    async function check(records: Rec[], subjectCN = "host.test", cert = LE) {
      const dns = mockDns((q) =>
        q.type === "CAA"
          ? packetWith(records.map((data) => ({ name: q.name, type: "CAA" as const, data })))
          : packetWith([]),
      );
      const tls = mockTls(() => fakeHandshake(fakeCert({ ...cert, subjectCN })));
      return runCaaCheck("host.test", opts, dns, tls);
    }

    it("lets issuewild forbid a wildcard certificate that issue would allow", async () => {
      const r = await check(
        [
          { tag: "issue", value: "letsencrypt.org" },
          { tag: "issuewild", value: ";" },
        ],
        "*.host.test",
      );
      expect(r.ok).toBe(false);
      expect(r.errors.join(" ")).toMatch(/not permitted/);
    });

    it("checks a wildcard certificate against issuewild only, when there is one", async () => {
      const r = await check(
        [
          { tag: "issue", value: "letsencrypt.org" },
          { tag: "issuewild", value: "digicert.com" },
        ],
        "*.host.test",
      );
      expect(r.ok).toBe(false);
    });

    it("falls back to issue for a wildcard certificate without issuewild", async () => {
      const r = await check([{ tag: "issue", value: "letsencrypt.org" }], "*.host.test");
      expect(r.ok).toBe(true);
      expect(r.matchedTag).toBe("letsencrypt.org");
    });

    it("ignores issuewild for a non-wildcard certificate", async () => {
      const r = await check([
        { tag: "issue", value: "digicert.com" },
        { tag: "issuewild", value: "letsencrypt.org" },
      ]);
      expect(r.ok).toBe(false);
    });

    it("does not restrict issuance when there is no issue property (only iodef)", async () => {
      const r = await check([{ tag: "iodef", value: "mailto:abuse@example.test" }]);
      expect(r).toMatchObject({ ok: true, errors: [] });
      expect(r.records).toHaveLength(1);
    });

    it("does not restrict a non-wildcard certificate when there is only issuewild", async () => {
      const r = await check([{ tag: "issuewild", value: "digicert.com" }]);
      expect(r).toMatchObject({ ok: true, errors: [] });
    });

    it("matches tags case-insensitively", async () => {
      expect((await check([{ tag: "Issue", value: "digicert.com" }])).ok).toBe(false);
      expect((await check([{ tag: "ISSUE", value: "letsencrypt.org" }])).ok).toBe(true);
      const wild = await check(
        [
          { tag: "issue", value: "letsencrypt.org" },
          { tag: "IssueWild", value: ";" },
        ],
        "*.host.test",
      );
      expect(wild.ok).toBe(false);
    });

    it("keeps the tag as published in the returned records", async () => {
      const r = await check([{ tag: "Issue", value: "letsencrypt.org" }]);
      expect(r.records[0]?.tag).toBe("Issue");
    });
  });
});
