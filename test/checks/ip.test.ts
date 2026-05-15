import { describe, expect, it } from "vitest";
import { runIpCheck } from "../../src/checks/ip.ts";
import { resolveOptions } from "../../src/options.ts";
import {
  fakeCert,
  fakeHandshake,
  mockDns,
  mockTls,
  packetWith,
} from "../helpers/mockTransports.ts";

const opts = resolveOptions("host.test");

describe("runIpCheck", () => {
  it("reports both families reachable", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : q.type === "AAAA"
          ? packetWith([{ name: q.name, type: "AAAA", data: "::1" }])
          : packetWith([]),
    );
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runIpCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(true);
    expect(r.ipv4.reachable).toBe(true);
    expect(r.ipv6.reachable).toBe(true);
  });

  it("reports v4 missing", async () => {
    const dns = mockDns((q) =>
      q.type === "AAAA"
        ? packetWith([{ name: q.name, type: "AAAA", data: "::1" }])
        : packetWith([]),
    );
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runIpCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(false);
    expect(r.ipv4.reachable).toBe(false);
    expect(r.errors.join(" ")).toMatch(/no address records/);
  });

  it("reports unreachable when TLS fails", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const tls = mockTls(() => {
      throw new Error("handshake fail");
    });
    const r = await runIpCheck("host.test", opts, dns, tls);
    expect(r.ok).toBe(false);
    expect(r.ipv4.reachable).toBe(false);
    expect(r.ipv6.reachable).toBe(false);
  });

  it("captures DNS errors", async () => {
    const dns = mockDns(() => {
      throw new Error("dns down");
    });
    const tls = mockTls(() => fakeHandshake(fakeCert()));
    const r = await runIpCheck("host.test", opts, dns, tls);
    expect(r.ipv4.error).toBe("dns down");
    expect(r.ipv6.error).toBe("dns down");
  });

  it("uses first reachable address per family", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([
            { name: q.name, type: "A", data: "192.0.2.1" },
            { name: q.name, type: "A", data: "192.0.2.2" },
          ])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    let calls = 0;
    const tls = mockTls(() => {
      calls++;
      if (calls === 1) throw new Error("first fails");
      return fakeHandshake(fakeCert());
    });
    const r = await runIpCheck("host.test", opts, dns, tls);
    expect(r.ipv4.reachable).toBe(true);
  });
});
