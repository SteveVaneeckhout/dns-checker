import { describe, expect, it } from "vitest";
import type { Answer } from "dns-packet";
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

  it("reports signed=false when queried name CNAMEs into an unsigned zone", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const parent = makeZone("parent.tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const dsParent = makeDsForChild(tld, "parent.tld", parent);

    const cnameRrset: Answer[] = [
      { name: "host.parent.tld", type: "CNAME", data: "target.other-tld" },
    ];
    const cnameSig = signRrset(cnameRrset, "CNAME", parent, "host.parent.tld");

    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DNSKEY" && name === "tld")
          return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
        if (type === "DNSKEY" && name === "parent.tld")
          return buildPacket(parent.dnskeyAnswers, [parent.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DS" && name === "parent.tld")
          return buildPacket(dsParent.records, [dsParent.rrsig]);
        if (type === "A" && name === "host.parent.tld") return buildPacket(cnameRrset, [cnameSig]);
        return buildPacket([], []);
      },
    };

    const result = await validateChain("host.parent.tld", transport, [anchor]);
    expect(result.signed).toBe(false);
    expect(result.chainValid).toBe(false);
    expect(result.chain.map((c) => c.zone)).toEqual([".", "tld", "parent.tld"]);
    expect(result.errors.join(" ")).toMatch(/target is insecure/);
  });

  it("reports signed=true when queried name has a signed CNAME to a signed target", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const parent = makeZone("parent.tld");
    const otherTld = makeZone("other-tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const dsParent = makeDsForChild(tld, "parent.tld", parent);
    const dsOther = makeDsForChild(root, "other-tld", otherTld);

    const cnameRrset: Answer[] = [
      { name: "host.parent.tld", type: "CNAME", data: "target.other-tld" },
    ];
    const cnameSig = signRrset(cnameRrset, "CNAME", parent, "host.parent.tld");
    const targetA: Answer[] = [{ name: "target.other-tld", type: "A", data: "192.0.2.5" }];
    const targetSig = signRrset(targetA, "A", otherTld, "target.other-tld");

    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DNSKEY" && name === "tld")
          return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
        if (type === "DNSKEY" && name === "parent.tld")
          return buildPacket(parent.dnskeyAnswers, [parent.dnskeySig]);
        if (type === "DNSKEY" && name === "other-tld")
          return buildPacket(otherTld.dnskeyAnswers, [otherTld.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DS" && name === "parent.tld")
          return buildPacket(dsParent.records, [dsParent.rrsig]);
        if (type === "DS" && name === "other-tld")
          return buildPacket(dsOther.records, [dsOther.rrsig]);
        if (type === "A" && name === "host.parent.tld") return buildPacket(cnameRrset, [cnameSig]);
        if (type === "A" && name === "target.other-tld") return buildPacket(targetA, [targetSig]);
        return buildPacket([], []);
      },
    };

    const result = await validateChain("host.parent.tld", transport, [anchor]);
    expect(result.signed).toBe(true);
    expect(result.chainValid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("reports signed=false when the queried name's CNAME RRset is unsigned", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const parent = makeZone("parent.tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const dsParent = makeDsForChild(tld, "parent.tld", parent);

    const cnameRrset: Answer[] = [
      { name: "host.parent.tld", type: "CNAME", data: "target.example" },
    ];

    const transport: DnsTransport = {
      async query({ type, name }) {
        if (type === "DNSKEY" && name === ".")
          return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
        if (type === "DNSKEY" && name === "tld")
          return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
        if (type === "DNSKEY" && name === "parent.tld")
          return buildPacket(parent.dnskeyAnswers, [parent.dnskeySig]);
        if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
        if (type === "DS" && name === "parent.tld")
          return buildPacket(dsParent.records, [dsParent.rrsig]);
        if (type === "A" && name === "host.parent.tld") return buildPacket(cnameRrset, []); // no RRSIG on the CNAME
        return buildPacket([], []);
      },
    };

    const result = await validateChain("host.parent.tld", transport, [anchor]);
    expect(result.signed).toBe(false);
    expect(result.errors.join(" ")).toMatch(/CNAME host\.parent\.tld is unsigned/);
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
