import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { apexAndWww, runRedirectCheck, startUrls } from "../../src/checks/redirects.ts";
import type { HttpFetchOptions } from "../../src/net/http.ts";
import { resolveOptions } from "../../src/options.ts";
import { mockDns, mockHttp, packetWith } from "../helpers/mockTransports.ts";

const V4 = "192.0.2.1";
const V6 = "2001:db8::1";

interface Page {
  status: number;
  location?: string;
}
type Site = Record<string, Page>;

/** A healthy site whose canonical origin is https://www.host.test. */
const WWW_SITE: Site = {
  "http://host.test/": { status: 301, location: "https://host.test/" },
  "http://www.host.test/": { status: 301, location: "https://www.host.test/" },
  "https://host.test/": { status: 301, location: "https://www.host.test/" },
  "https://www.host.test/": { status: 200 },
};

interface WebOptions {
  /** Hosts with an A record; default host.test and www.host.test. */
  v4Hosts?: string[];
  /** Hosts with an AAAA record; default none. */
  v6Hosts?: string[];
  /** What the IPv6 addresses serve; default the same site. */
  v6Site?: Site;
}

function fakeWeb(site: Site, web: WebOptions = {}) {
  const v4Hosts = web.v4Hosts ?? ["host.test", "www.host.test"];
  const v6Hosts = web.v6Hosts ?? [];
  const requests: HttpFetchOptions[] = [];
  const dns = mockDns((q) => {
    if (q.type === "A" && v4Hosts.includes(q.name)) {
      return packetWith([{ name: q.name, type: "A", data: V4 }]);
    }
    if (q.type === "AAAA" && v6Hosts.includes(q.name)) {
      return packetWith([{ name: q.name, type: "AAAA", data: V6 }]);
    }
    return packetWith([]);
  });
  const http = mockHttp((o) => {
    requests.push(o);
    const page = (o.address === V6 ? (web.v6Site ?? site) : site)[o.url] ?? { status: 404 };
    return {
      status: page.status,
      headers: page.location !== undefined ? { location: page.location } : {},
      body: Buffer.alloc(0),
      truncated: false,
    };
  });
  return { dns, http, requests };
}

const opts = resolveOptions("host.test");

describe("apexAndWww / startUrls", () => {
  it("adds www to an apex and strips it from a www name", () => {
    expect(apexAndWww("host.test")).toEqual({ apex: "host.test", www: "www.host.test" });
    expect(apexAndWww("www.host.test")).toEqual({ apex: "host.test", www: "www.host.test" });
  });

  it("lists the four entry points", () => {
    expect(startUrls("host.test", "www.host.test")).toEqual([
      "http://host.test/",
      "http://www.host.test/",
      "https://host.test/",
      "https://www.host.test/",
    ]);
  });
});

describe("runRedirectCheck", () => {
  it("passes a site where all four entry points end at https://www", async () => {
    const { dns, http } = fakeWeb(WWW_SITE);
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.errors).toEqual([]);
    expect(r.warnings).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.apex).toBe("host.test");
    expect(r.www).toBe("www.host.test");
    expect(r.canonicalOrigin).toBe("https://www.host.test");
    expect(r.ipv6).toEqual({ available: false, chains: [] });
    const chains = r.ipv4.chains;
    expect(chains.map((c) => c.finalUrl)).toEqual(Array(4).fill("https://www.host.test/"));
    // 3 of 4 entry points redirect; http://apex takes two hops via https://apex.
    expect(chains.map((c) => c.hops.length - 1)).toEqual([2, 1, 1, 0]);
    expect(chains[0]?.hops.map((h) => h.url)).toEqual([
      "http://host.test/",
      "https://host.test/",
      "https://www.host.test/",
    ]);
    expect(chains[0]?.hops[0]).toEqual({
      url: "http://host.test/",
      address: V4,
      status: 301,
      location: "https://host.test/",
    });
  });

  it("passes a site whose canonical origin is the apex", async () => {
    const { dns, http } = fakeWeb({
      "http://host.test/": { status: 308, location: "https://host.test/" },
      "http://www.host.test/": { status: 301, location: "https://www.host.test/" },
      "https://www.host.test/": { status: 301, location: "https://host.test/" },
      "https://host.test/": { status: 200 },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.canonicalOrigin).toBe("https://host.test");
  });

  it("accepts the www name as input", async () => {
    const { dns, http } = fakeWeb(WWW_SITE);
    const r = await runRedirectCheck("www.host.test", opts, dns, http);
    expect(r.ok).toBe(true);
    expect(r.apex).toBe("host.test");
  });

  it("requests one hop at a time with the hop's own host name", async () => {
    const { dns, http, requests } = fakeWeb(WWW_SITE);
    await runRedirectCheck("host.test", opts, dns, http);
    expect(requests.every((q) => q.maxRedirects === 0)).toBe(true);
    expect(requests.every((q) => q.servername === new URL(q.url).hostname)).toBe(true);
  });

  it("resolves a relative Location against the current URL", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://www.host.test/": { status: 301, location: "/en/" },
      "https://www.host.test/en/": { status: 200 },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(true);
    expect(r.canonicalOrigin).toBe("https://www.host.test");
  });

  it("warns when http://apex skips https://apex (HSTS preload)", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "http://host.test/": { status: 301, location: "https://www.host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(true);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toMatch(
      /^\[IPv4\] http:\/\/host\.test\/ first redirects to https:\/\/www\.host\.test\/; redirect to https:\/\/host\.test\/ first/,
    );
    expect(r.ipv4.chains[0]?.warnings).toHaveLength(1);
  });

  it("fails a temporary redirect", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://host.test/": { status: 302, location: "https://www.host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    // Both http://apex (via https://apex) and https://apex take the 302; it is listed once.
    expect(r.errors).toEqual([
      "[IPv4] https://host.test/ redirects with a temporary 302; use 301 or 308 for a permanent move",
    ]);
    expect(r.ipv4.chains.map((c) => c.errors.length)).toEqual([1, 0, 1, 0]);
  });

  it("leaves a temporary redirect within the canonical origin alone (language redirect)", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://www.host.test/": { status: 302, location: "/en/" },
      "https://www.host.test/en/": { status: 200 },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.errors).toEqual([]);
    expect(r.warnings).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.canonicalOrigin).toBe("https://www.host.test");
    expect(r.ipv4.chains.map((c) => c.finalUrl)).toEqual(
      Array(4).fill("https://www.host.test/en/"),
    );
  });

  it("still fails a language redirect that ends in an error status", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://www.host.test/": { status: 302, location: "/en/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual(["[IPv4] https://www.host.test/en/ answers HTTP 404"]);
  });

  it("judges the move to another host, not a same-host 302 before it", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://host.test/": { status: 302, location: "/en/" },
      "https://host.test/en/": { status: 301, location: "https://www.host.test/en/" },
      "https://www.host.test/en/": { status: 200 },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it("lists a warning seen over IPv4 and IPv6 once, with both families", async () => {
    const site = {
      ...WWW_SITE,
      "http://host.test/": { status: 301, location: "https://www.host.test/" },
    };
    const { dns, http } = fakeWeb(site, { v6Hosts: ["host.test", "www.host.test"] });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(true);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toMatch(/^\[IPv4, IPv6\] http:\/\/host\.test\/ first redirects/);
  });

  it("fails a temporary redirect from HTTP to HTTPS on the same host", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "http://www.host.test/": { status: 307, location: "https://www.host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual([
      "[IPv4] http://www.host.test/ redirects with a temporary 307; use 301 or 308 for a permanent move",
    ]);
  });

  it("fails when both HTTPS names serve content without redirecting", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://host.test/": { status: 200 },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.canonicalOrigin).toBe("https://host.test");
    expect(r.errors).toEqual([
      "[IPv4] http://www.host.test/ ends at https://www.host.test/, not on https://host.test",
      "[IPv4] https://www.host.test/ ends at https://www.host.test/, not on https://host.test",
    ]);
  });

  it("checks against the canonicalOrigin option", async () => {
    const { dns, http } = fakeWeb(WWW_SITE);
    const r = await runRedirectCheck(
      "host.test",
      resolveOptions("host.test", { canonicalOrigin: "https://HOST.test/any/path" }),
      dns,
      http,
    );
    expect(r.canonicalOrigin).toBe("https://host.test");
    expect(r.ok).toBe(false);
    expect(r.errors).toHaveLength(4);
  });

  it("fails when the www name has no address", async () => {
    const { dns, http } = fakeWeb(WWW_SITE, { v4Hosts: ["host.test"] });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual(["[IPv4] no IPv4 address for www.host.test"]);
    // The apex chains redirect to www too, so all four hit the missing address.
    expect(r.ipv4.chains.map((c) => c.errors.length)).toEqual([1, 1, 1, 1]);
  });

  it("fails a redirect loop", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://www.host.test/": { status: 301, location: "https://host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.canonicalOrigin).toBeUndefined();
    expect(r.errors).toContain(
      "[IPv4] https://www.host.test/ loops: https://www.host.test/ was already requested",
    );
  });

  it("gives up on an endless chain of redirects", async () => {
    const dns = mockDns((q) =>
      q.type === "A" ? packetWith([{ name: q.name, type: "A", data: V4 }]) : packetWith([]),
    );
    let n = 0;
    const http = mockHttp(() => ({
      status: 301,
      headers: { location: `/${++n}` },
      body: Buffer.alloc(0),
      truncated: false,
    }));
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ipv4.chains[0]?.hops).toHaveLength(10);
    expect(r.ipv4.chains[0]?.errors).toEqual(["http://host.test/ takes more than 9 redirects"]);
  });

  it("fails a downgrade from HTTPS to HTTP", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://host.test/": { status: 301, location: "http://www.host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(
      r.errors.some((e) => /https:\/\/host\.test\/ redirects from HTTPS to HTTP/.test(e)),
    ).toBe(true);
  });

  it("fails a chain that ends in an error status", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "https://www.host.test/": { status: 503 },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.canonicalOrigin).toBeUndefined();
    // All four chains end at the same 503; it is listed once.
    expect(r.errors).toEqual(["[IPv4] https://www.host.test/ answers HTTP 503"]);
  });

  it("fails a redirect without a usable Location header", async () => {
    const { dns, http } = fakeWeb({
      ...WWW_SITE,
      "http://host.test/": { status: 301 },
      "http://www.host.test/": { status: 301, location: "ftp://www.host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.errors).toContain("[IPv4] http://host.test/: 301 without a Location header");
    expect(r.errors).toContain(
      "[IPv4] http://www.host.test/: invalid Location header: ftp://www.host.test/",
    );
  });

  it("reports a failed request", async () => {
    const dns = mockDns((q) =>
      q.type === "A" ? packetWith([{ name: q.name, type: "A", data: V4 }]) : packetWith([]),
    );
    const http = mockHttp((o) => {
      if (o.url.startsWith("http:")) throw new Error("connection refused");
      return { status: 200, headers: {}, body: Buffer.alloc(0), truncated: false };
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.errors).toContain("[IPv4] http://host.test/: connection refused");
  });

  it("checks IPv4 and IPv6 separately and catches a difference", async () => {
    const { dns, http } = fakeWeb(WWW_SITE, {
      v6Hosts: ["host.test", "www.host.test"],
      v6Site: { ...WWW_SITE, "https://host.test/": { status: 200 } },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ipv6.available).toBe(true);
    expect(r.canonicalOrigin).toBe("https://www.host.test");
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual([
      "[IPv6] http://host.test/ ends at https://host.test/, not on https://www.host.test",
      "[IPv6] https://host.test/ ends at https://host.test/, not on https://www.host.test",
    ]);
  });

  it("lists an error seen over IPv4 and IPv6 once, with both families", async () => {
    const { dns, http } = fakeWeb(
      { ...WWW_SITE, "http://www.host.test/": { status: 307, location: "https://www.host.test/" } },
      { v6Hosts: ["host.test", "www.host.test"] },
    );
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.errors).toEqual([
      "[IPv4, IPv6] http://www.host.test/ redirects with a temporary 307; use 301 or 308 for a permanent move",
    ]);
  });

  it("reports failed DNS lookups and no addresses at all", async () => {
    const dns = mockDns(() => {
      throw new Error("dns broken");
    });
    const { http } = fakeWeb(WWW_SITE);
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.ok).toBe(false);
    expect(r.errors).toContain("A lookup for host.test: dns broken");
    expect(r.errors).toContain("AAAA lookup for www.host.test: dns broken");
    expect(r.errors.at(-1)).toBe("no IPv4 or IPv6 address for host.test or www.host.test");
  });

  it("fails a canonical origin that is not HTTPS", async () => {
    const { dns, http } = fakeWeb({
      "http://host.test/": { status: 301, location: "http://www.host.test/" },
      "http://www.host.test/": { status: 200 },
      "https://host.test/": { status: 301, location: "http://www.host.test/" },
      "https://www.host.test/": { status: 301, location: "http://www.host.test/" },
    });
    const r = await runRedirectCheck("host.test", opts, dns, http);
    expect(r.canonicalOrigin).toBe("http://www.host.test");
    expect(r.errors).toContain("canonical origin http://www.host.test is not HTTPS");
  });
});
