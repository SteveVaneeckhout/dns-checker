import { describe, expect, it } from "vitest";
import { runDnssecCheck } from "../../src/checks/dnssec.ts";
import { resolveOptions } from "../../src/options.ts";
import {
  buildPacket,
  makeDsForChild,
  makeTrustAnchorFor,
  makeZone,
} from "../helpers/dnssecFixtures.ts";
import { mockDns, packetWith } from "../helpers/mockTransports.ts";

describe("runDnssecCheck", () => {
  it("reports not ok when root DNSKEY query fails", async () => {
    const dns = mockDns(() => packetWith([]));
    const r = await runDnssecCheck("example.test", resolveOptions("example.test"), dns);
    expect(r.ok).toBe(false);
    expect(r.signed).toBe(false);
  });

  it("returns a populated chain when the synthetic DNSSEC chain validates", async () => {
    const root = makeZone(".");
    const tld = makeZone("tld");
    const apex = makeZone("example.tld");
    const anchor = makeTrustAnchorFor(root);
    const dsTld = makeDsForChild(root, "tld", tld);
    const dsApex = makeDsForChild(tld, "example.tld", apex);

    const dns = mockDns(({ type, name }) => {
      if (type === "DNSKEY" && name === ".")
        return buildPacket(root.dnskeyAnswers, [root.dnskeySig]);
      if (type === "DNSKEY" && name === "tld")
        return buildPacket(tld.dnskeyAnswers, [tld.dnskeySig]);
      if (type === "DNSKEY" && name === "example.tld")
        return buildPacket(apex.dnskeyAnswers, [apex.dnskeySig]);
      if (type === "DS" && name === "tld") return buildPacket(dsTld.records, [dsTld.rrsig]);
      if (type === "DS" && name === "example.tld")
        return buildPacket(dsApex.records, [dsApex.rrsig]);
      return buildPacket([], []);
    });

    const opts = resolveOptions("example.tld", { trustAnchors: [anchor] });
    const r = await runDnssecCheck("example.tld", opts, dns);

    expect(r.ok).toBe(true);
    expect(r.chainValid).toBe(true);
    expect(r.signed).toBe(true);
    expect(r.chain.map((s) => s.zone)).toEqual([".", "tld", "example.tld"]);
    expect(r.chain.every((s) => s.dsVerified && s.keysVerified)).toBe(true);
  });
});
