import { describe, expect, it } from "vitest";
import { normalizeHostname, resolveOptions } from "../src/options.ts";

describe("resolveOptions", () => {
  it("applies defaults when no options given", () => {
    const r = resolveOptions("example.com");
    expect(r.url).toBe("https://example.com/");
    expect(r.timeoutMs).toBe(5000);
    expect(r.resolver).toBe("1.1.1.1");
    expect(r.bodyHashLimit).toBe(1024 * 1024);
  });

  it("respects supplied options", () => {
    const r = resolveOptions("example.com", {
      url: "https://example.com/health",
      timeoutMs: 1000,
      resolver: "9.9.9.9",
      bodyHashLimit: 1024,
    });
    expect(r.url).toBe("https://example.com/health");
    expect(r.timeoutMs).toBe(1000);
    expect(r.resolver).toBe("9.9.9.9");
    expect(r.bodyHashLimit).toBe(1024);
  });
});

describe("normalizeHostname", () => {
  it("lowercases, trims, strips trailing dot", () => {
    expect(normalizeHostname("  Example.COM.  ")).toBe("example.com");
  });

  it("throws on empty hostname", () => {
    expect(() => normalizeHostname("   ")).toThrow(/empty/);
  });
});
