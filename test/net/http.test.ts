import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { createHttpTransport, parseHttpResponse, resolveRedirect } from "../../src/net/http.ts";
import { startHttpsServer, startTlsServer } from "../helpers/tlsServer.ts";

describe("createHttpTransport (local server)", () => {
  const get = (port: number, url = "https://localhost/page?q=1", extra = {}) =>
    createHttpTransport().get({
      address: "127.0.0.1",
      port,
      servername: "localhost",
      url,
      timeoutMs: 2000,
      ...extra,
    });

  it("sends a GET request and parses the response", async () => {
    let request = "";
    await using server = await startTlsServer((socket) => {
      socket.once("data", (d: Buffer) => {
        request = d.toString("latin1");
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello");
      });
    });
    const r = await get(server.port);
    expect(request).toMatch(/^GET \/page\?q=1 HTTP\/1\.1\r\nHost: localhost\r\n/);
    expect(r.status).toBe(200);
    expect(r.headers["x-test"]).toBe("yes");
    expect(r.body.toString()).toBe("hello");
    expect(r.truncated).toBe(false);
  });

  it("follows a same-host redirect", async () => {
    let n = 0;
    await using server = await startTlsServer((socket) => {
      socket.once("data", () => {
        socket.end(
          n++ === 0
            ? "HTTP/1.1 301 Moved\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
            : "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
        );
      });
    });
    const r = await get(server.port);
    expect(r.status).toBe(200);
    expect(r.body.toString()).toBe("done");
  });

  it("stops reading once the body limit plus header allowance is reached", async () => {
    await using server = await startHttpsServer(`HTTP/1.1 200 OK\r\n\r\n${"x".repeat(200_000)}`);
    const r = await get(server.port, undefined, { bodyLimit: 10 });
    expect(r.body.length).toBe(10);
    expect(r.truncated).toBe(true);
  });

  it("rejects a malformed response", async () => {
    await using server = await startHttpsServer("garbage\r\n\r\n");
    await expect(get(server.port)).rejects.toThrow(/malformed HTTP response/);
  });

  it("times out when the server never responds", async () => {
    await using server = await startTlsServer();
    await expect(get(server.port, undefined, { timeoutMs: 150 })).rejects.toThrow(
      /HTTP fetch timed out after 150ms/,
    );
  });
});

describe("parseHttpResponse", () => {
  it("parses Content-Length body", () => {
    const r = parseHttpResponse(
      Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "utf8"),
      100,
    );
    expect(r?.status).toBe(200);
    expect(r?.body.toString()).toBe("hello");
    expect(r?.truncated).toBe(false);
  });

  it("returns null when Content-Length body is not yet complete", () => {
    expect(
      parseHttpResponse(
        Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", "utf8"),
        1024,
      ),
    ).toBeNull();
  });

  it("returns null when headers are incomplete", () => {
    expect(parseHttpResponse(Buffer.from("HTTP/1.1 200 OK\r\nNo end yet", "utf8"), 100)).toBeNull();
  });

  it("returns null when status line is malformed", () => {
    expect(parseHttpResponse(Buffer.from("not http\r\n\r\n", "utf8"), 100)).toBeNull();
  });

  it("parses chunked body", () => {
    const r = parseHttpResponse(
      Buffer.from(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nfoo\r\n0\r\n\r\n",
        "utf8",
      ),
      1024,
    );
    expect(r?.body.toString()).toBe("hellofoo");
    expect(r?.truncated).toBe(false);
  });

  it("truncates chunked body at bodyLimit", () => {
    const r = parseHttpResponse(
      Buffer.from(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "utf8",
      ),
      3,
    );
    expect(r?.body.length).toBe(3);
    expect(r?.truncated).toBe(true);
  });

  it("truncates chunked body at exact bodyLimit (next chunk fills it)", () => {
    const r = parseHttpResponse(
      Buffer.from(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nbar\r\n0\r\n\r\n",
        "utf8",
      ),
      5,
    );
    expect(r?.body.length).toBe(5);
    expect(r?.truncated).toBe(true);
  });

  it("returns null on bad chunk size", () => {
    expect(
      parseHttpResponse(
        Buffer.from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nx\r\n", "utf8"),
        100,
      ),
    ).toBeNull();
  });

  it("returns null when chunked body lacks data", () => {
    expect(
      parseHttpResponse(
        Buffer.from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi", "utf8"),
        100,
      ),
    ).toBeNull();
  });

  it("parses body without content-length or chunked (read-to-close)", () => {
    const r = parseHttpResponse(Buffer.from("HTTP/1.1 200 OK\r\n\r\nbody", "utf8"), 100);
    expect(r?.body.toString()).toBe("body");
  });

  it("truncates read-to-close body at bodyLimit", () => {
    const r = parseHttpResponse(
      Buffer.from("HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(200), "utf8"),
      10,
    );
    expect(r?.body.length).toBe(10);
    expect(r?.truncated).toBe(true);
  });

  it("collects headers, lowercased", () => {
    const r = parseHttpResponse(
      Buffer.from("HTTP/1.1 200 OK\r\nServer: a\r\nETag: x\r\nContent-Length: 0\r\n\r\n", "utf8"),
      0,
    );
    expect(r?.headers["server"]).toBe("a");
    expect(r?.headers["etag"]).toBe("x");
  });

  it("ignores malformed header lines", () => {
    const r = parseHttpResponse(
      Buffer.from("HTTP/1.1 200 OK\r\nbadheader\r\nContent-Length: 0\r\n\r\n", "utf8"),
      100,
    );
    expect(r?.status).toBe(200);
  });
});

describe("resolveRedirect", () => {
  it("follows a same-host absolute redirect", () => {
    const next = resolveRedirect(
      301,
      "https://example.com/en",
      "https://example.com/",
      "example.com",
    );
    expect(next?.toString()).toBe("https://example.com/en");
  });

  it("follows a same-host relative redirect", () => {
    const next = resolveRedirect(302, "/en", "https://example.com/", "example.com");
    expect(next?.toString()).toBe("https://example.com/en");
  });

  it("returns null for cross-host redirect (apex → www)", () => {
    expect(
      resolveRedirect(301, "https://www.example.com/", "https://example.com/", "example.com"),
    ).toBeNull();
  });

  it("returns null for non-redirect status", () => {
    expect(resolveRedirect(200, "/en", "https://example.com/", "example.com")).toBeNull();
  });

  it("returns null for missing Location header", () => {
    expect(resolveRedirect(302, undefined, "https://example.com/", "example.com")).toBeNull();
  });

  it("handles all 3xx redirect statuses", () => {
    for (const status of [301, 302, 303, 307, 308]) {
      expect(resolveRedirect(status, "/x", "https://example.com/", "example.com")?.toString()).toBe(
        "https://example.com/x",
      );
    }
  });
});

describe("createHttpTransport", () => {
  it("rejects an invalid URL", async () => {
    const http = createHttpTransport();
    await expect(
      http.get({ address: "127.0.0.1", servername: "x", url: "not a url" }),
    ).rejects.toThrow(/invalid URL/);
  });

  it("rejects when the connection cannot be established", async () => {
    const http = createHttpTransport();
    await expect(
      http.get({
        address: "127.0.0.1",
        port: 1,
        servername: "localhost",
        url: "https://localhost/",
        timeoutMs: 500,
      }),
    ).rejects.toThrow();
  });
});
