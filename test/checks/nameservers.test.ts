import { describe, expect, it } from "vitest";
import { runNameserverCheck } from "../../src/checks/nameservers.ts";
import { resolveOptions } from "../../src/options.ts";
import { mockDns, packetWith } from "../helpers/mockTransports.ts";

const opts = resolveOptions("example.test");

describe("runNameserverCheck", () => {
  it("reports ok when all NS reachable over both families", async () => {
    const dns = mockDns((q) => {
      if (q.type === "NS")
        return packetWith([
          { name: q.name, type: "NS", data: "ns1.example.test" },
          { name: q.name, type: "NS", data: "ns2.example.test" },
        ]);
      if (q.type === "A") return packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }]);
      if (q.type === "AAAA") return packetWith([{ name: q.name, type: "AAAA", data: "::1" }]);
      return packetWith([{ name: q.name, type: "SOA", data: { mname: "ns1", rname: "h" } }]);
    });
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.ok).toBe(true);
    expect(r.nameservers.length).toBe(2);
  });

  it("captures NS query failure", async () => {
    const dns = mockDns(() => {
      throw new Error("ns fail");
    });
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/ns fail/);
  });

  it("reports no NS records", async () => {
    const dns = mockDns(() => packetWith([]));
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.ok).toBe(false);
    expect(r.errors).toContain("no NS records found");
  });

  it("captures missing A records for an NS", async () => {
    const dns = mockDns((q) => {
      if (q.type === "NS")
        return packetWith([{ name: q.name, type: "NS", data: "ns.example.test" }]);
      if (q.type === "AAAA") return packetWith([{ name: q.name, type: "AAAA", data: "::1" }]);
      if (q.type === "SOA")
        return packetWith([{ name: q.name, type: "SOA", data: { mname: "x", rname: "y" } }]);
      return packetWith([]);
    });
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.ok).toBe(false);
    expect(r.nameservers[0]?.ipv4.error).toBe("no address records");
  });

  it("reports unreachable NS over v4 when SOA probe fails", async () => {
    const dns = mockDns((q) => {
      if (q.type === "NS")
        return packetWith([{ name: q.name, type: "NS", data: "ns.example.test" }]);
      if (q.type === "A") return packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }]);
      if (q.type === "AAAA") return packetWith([{ name: q.name, type: "AAAA", data: "::1" }]);
      if (q.type === "SOA" && q.server === "192.0.2.1") throw new Error("timeout");
      return packetWith([{ name: q.name, type: "SOA", data: { mname: "x", rname: "y" } }]);
    });
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/not reachable over IPv4/);
  });

  it("reports unreachable NS over v6 when SOA probe over IPv6 fails", async () => {
    const dns = mockDns((q) => {
      if (q.type === "NS")
        return packetWith([{ name: q.name, type: "NS", data: "ns.example.test" }]);
      if (q.type === "A") return packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }]);
      if (q.type === "AAAA") return packetWith([{ name: q.name, type: "AAAA", data: "::1" }]);
      if (q.type === "SOA" && q.server === "::1") throw new Error("v6 timeout");
      return packetWith([{ name: q.name, type: "SOA", data: { mname: "x", rname: "y" } }]);
    });
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/not reachable over IPv6/);
  });

  it("captures A lookup failure for an NS", async () => {
    const dns = mockDns((q) => {
      if (q.type === "NS")
        return packetWith([{ name: q.name, type: "NS", data: "ns.example.test" }]);
      if (q.type === "A") throw new Error("a query failed");
      if (q.type === "AAAA") return packetWith([{ name: q.name, type: "AAAA", data: "::1" }]);
      return packetWith([{ name: q.name, type: "SOA", data: { mname: "x", rname: "y" } }]);
    });
    const r = await runNameserverCheck("example.test", opts, dns);
    expect(r.nameservers[0]?.ipv4.error).toBe("a query failed");
  });
});
