import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { runSamenessCheck } from "../../src/checks/sameness.ts";
import { resolveOptions } from "../../src/options.ts";
import { mockDns, mockHttp, packetWith } from "../helpers/mockTransports.ts";

const opts = resolveOptions("host.test");

describe("runSamenessCheck", () => {
  it("returns ok and similarity=1 when 200/200 bodies are identical", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp(() => ({
      status: 200,
      headers: {},
      body: Buffer.from("hello"),
      truncated: false,
    }));
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(true);
    expect(r.similarity).toBe(1);
    expect(r.match).toBe(false);
    expect(r.ipv4Hash).toBeUndefined();
    expect(r.ipv6Hash).toBeUndefined();
  });

  it("returns similarity<1 and match=false when 200/200 bodies differ", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp((o) => ({
      status: 200,
      headers: {},
      body: Buffer.from(o.address === "::1" ? "totally different content here" : "hello world"),
      truncated: false,
    }));
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(true);
    expect(r.match).toBe(false);
    expect(r.similarity).toBeDefined();
    expect(r.similarity!).toBeLessThan(1);
  });

  it("returns errors when one family is missing", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([]),
    );
    const http = mockHttp(() => ({
      status: 200,
      headers: {},
      body: Buffer.from(""),
      truncated: false,
    }));
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.match).toBe(false);
    expect(r.errors).toContain("no IPv6 address available");
  });

  it("captures DNS lookup errors", async () => {
    const dns = mockDns(() => {
      throw new Error("dns broken");
    });
    const http = mockHttp(() => ({
      status: 200,
      headers: {},
      body: Buffer.from(""),
      truncated: false,
    }));
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.errors.some((e) => /A lookup/.test(e))).toBe(true);
    expect(r.errors.some((e) => /AAAA lookup/.test(e))).toBe(true);
  });

  it("captures HTTP errors", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp((o) => {
      if (o.address === "192.0.2.1") throw new Error("ipv4 down");
      return { status: 200, headers: {}, body: Buffer.from("ok"), truncated: false };
    });
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.errors.join(" ")).toMatch(/ipv4 fetch/);
    expect(r.match).toBe(false);
  });

  it("matches when both families return identical cross-host redirects", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp(() => ({
      status: 301,
      headers: { location: "https://www.host.test/" },
      body: Buffer.from(""),
      truncated: false,
    }));
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.match).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("does not match when one family redirects and the other returns 200", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp((o) =>
      o.address === "192.0.2.1"
        ? { status: 200, headers: {}, body: Buffer.from(""), truncated: false }
        : {
            status: 301,
            headers: { location: "https://www.host.test/" },
            body: Buffer.from(""),
            truncated: false,
          },
    );
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.match).toBe(false);
  });

  it("hash factors in Location, so different redirect targets mismatch even with same body", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp((o) => ({
      status: 301,
      headers: {
        location: o.address === "192.0.2.1" ? "https://host.test/en" : "https://host.test/fr",
      },
      body: Buffer.from(""),
      truncated: false,
    }));
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.match).toBe(false);
    expect(r.ipv4Hash).not.toBe(r.ipv6Hash);
  });

  it("captures both HTTP errors", async () => {
    const dns = mockDns((q) =>
      q.type === "A"
        ? packetWith([{ name: q.name, type: "A", data: "192.0.2.1" }])
        : packetWith([{ name: q.name, type: "AAAA", data: "::1" }]),
    );
    const http = mockHttp(() => {
      throw new Error("net down");
    });
    const r = await runSamenessCheck("host.test", opts, dns, http);
    expect(r.errors.filter((e) => /fetch/.test(e)).length).toBe(2);
  });
});
