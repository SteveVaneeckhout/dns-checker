import { describe, expect, it } from "vitest";
import type { DnsTransport } from "../../src/net/dns.ts";
import { validateChain, verifyRecord } from "../../src/dnssec/chain.ts";
import {
  buildPacket,
  makeDsForChild,
  makeTrustAnchorFor,
  makeZone,
  signRrset,
} from "../helpers/dnssecFixtures.ts";

describe("validateChain", () => {
  it("validates a synthetic chain root → tld → example.tld", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const apex = makeZone("example.tld");
    const anchor = makeTrustAnchorFor(root);

    const dsTld = makeDsForChild(root, "tld", tld);
    const dsApex = makeDsForChild(tld, "example.tld", apex);

    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".") {
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        }
        if (type === "DNSKEY" && name === "tld") {
          return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
        }
        if (type === "DNSKEY" && name === "example.tld") {
          return buildPacket(apex.dnskeyAnswers, [apex.dnskeySig]);
        }
        if (type === "DS" && name === "tld") {
          return buildPacket(dsTld.records, [dsTld.rrsig]);
        }
        if (type === "DS" && name === "example.tld") {
          return buildPacket(dsApex.records, [dsApex.rrsig]);
        }
        return buildPacket([], []);
      },
    };

    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.chainValid).toBe(true);
    expect(result.signed).toBe(true);
    expect(result.chain.map((c) => c.zone)).toEqual([".", "tld", "example.tld"]);
    expect(result.finalZone).toBe("example.tld");
  });

  it("fails when root DNSKEY does not match anchor", async () => {
    const root = makeZone(".");
    const wrongAnchor = makeTrustAnchorFor(makeZone("."));
    const transport: DnsTransport = {
      async query() {
        return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
      },
    };
    const result = await validateChain("example.test", transport, [wrongAnchor]);
    expect(result.chainValid).toBe(false);
    expect(result.errors.join(" ")).toMatch(/trust anchor/);
  });

  it("fails when root DNSKEY RRSIG is missing", async () => {
    const root = makeZone(".");
    const anchor = makeTrustAnchorFor(root);
    const transport: DnsTransport = {
      async query() {
        return buildPacket(root.dnskeyAnswers, []);
      },
    };
    const result = await validateChain("example.test", transport, [anchor]);
    expect(result.chainValid).toBe(false);
    expect(result.errors.join(" ")).toMatch(/RRset missing or unsigned/);
  });

  it("fails when root DNSKEY RRSIG is tampered", async () => {
    const root = makeZone(".");
    const anchor = makeTrustAnchorFor(root);
    const other = makeZone(".");
    const transport: DnsTransport = {
      async query() {
        return buildPacket(root.dnskeyAnswers, [other.dnskeySig]);
      },
    };
    const result = await validateChain("example.test", transport, [anchor]);
    expect(result.chainValid).toBe(false);
    expect(result.errors.join(" ")).toMatch(/did not verify/);
  });

  it("skips zones with no DS (no zone cut)", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DNSKEY" && name === "tld")
          return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        // example.tld has no DS (not a cut)
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.chainValid).toBe(true);
    expect(result.finalZone).toBe("tld");
  });

  it("reports DS query failure", async () => {
    const root = makeZone(".");
    const anchor = makeTrustAnchorFor(root);
    const transport: DnsTransport = {
      async query({ type }) {
        if (type === "DNSKEY") return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        throw new Error("upstream error");
      },
    };
    const result = await validateChain("example.test", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/upstream error/);
  });

  it("reports DS without RRSIG", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, []);
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/DS .* is unsigned/);
  });

  it("reports invalid DS RRSIG", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const otherRoot = makeZone(".");
    const tamperedSig = signRrset(dsTld.records, "DS", otherRoot, "tld");
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [tamperedSig]);
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/RRSIG invalid/);
  });

  it("reports DNSKEY query failure for child", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DNSKEY" && name === "tld") throw new Error("dnskey fail");
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/dnskey fail/);
  });

  it("reports missing child DNSKEY", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DNSKEY" && name === "tld") return buildPacket([], []);
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/DNSKEY .* missing/);
  });

  it("reports when child DNSKEY does not match parent DS", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const wrong = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DNSKEY" && name === "tld")
          return buildPacket(wrong.dnskeyAnswers, [wrong.dnskeySig]);
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/no DNSKEY .* matches DS/);
  });

  it("reports when child DNSKEY RRSIG fails", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const tamperedDnskeyAnswers = tld.dnskeyAnswers;
    const otherTld = makeZone("tld");
    const tamperedSig = otherTld.dnskeySig;
    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DNSKEY" && name === "tld")
          return buildPacket(tamperedDnskeyAnswers, [tamperedSig]);
        return buildPacket([], []);
      },
    };
    const result = await validateChain("example.tld", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/RRSIG invalid/);
  });

  it("reports root DNSKEY exception", async () => {
    const root = makeZone(".");
    const anchor = makeTrustAnchorFor(root);
    const transport: DnsTransport = {
      async query() {
        throw new Error("boom");
      },
    };
    const result = await validateChain("example.test", transport, [anchor]);
    expect(result.errors.join(" ")).toMatch(/boom/);
  });
});

describe("verifyRecord", () => {
  it("returns verified for a properly signed RRset", async () => {
    const apex = makeZone("example.tld");
    const aSet = [{ name: "host.example.tld", type: "A" as const, data: "192.0.2.1" }];
    const sig = signRrset(aSet, "A", apex, "host.example.tld");
    const transport: DnsTransport = {
      async query() {
        return buildPacket(aSet, [sig]);
      },
    };
    const r = await verifyRecord("A", "host.example.tld", [apex.zsk.dnskey], transport);
    expect(r.verified).toBe(true);
    expect(r.answers.length).toBe(1);
  });

  it("returns not verified when no records", async () => {
    const transport: DnsTransport = {
      async query() {
        return buildPacket([], []);
      },
    };
    const r = await verifyRecord("A", "no.example.tld", [], transport);
    expect(r.verified).toBe(false);
    expect(r.error).toMatch(/no records/);
  });

  it("returns not verified when no RRSIG", async () => {
    const aSet = [{ name: "host.example.tld", type: "A" as const, data: "1.2.3.4" }];
    const transport: DnsTransport = {
      async query() {
        return buildPacket(aSet, []);
      },
    };
    const r = await verifyRecord("A", "host.example.tld", [], transport);
    expect(r.verified).toBe(false);
    expect(r.error).toMatch(/no RRSIG/);
  });

  it("captures transport error", async () => {
    const transport: DnsTransport = {
      async query() {
        throw new Error("network down");
      },
    };
    const r = await verifyRecord("A", "host.example.tld", [], transport);
    expect(r.verified).toBe(false);
    expect(r.error).toMatch(/network down/);
  });
});
