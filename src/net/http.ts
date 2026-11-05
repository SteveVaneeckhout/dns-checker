import { Buffer } from "node:buffer";
import { once } from "node:events";
import { addAbortSignal } from "node:stream";
import tls from "node:tls";

export interface HttpFetchOptions {
  address: string;
  port?: number;
  servername: string;
  url: string;
  timeoutMs?: number;
  bodyLimit?: number;
  maxRedirects?: number;
}

export interface HttpFetchResult {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  truncated: boolean;
}

export interface HttpTransport {
  get(opts: HttpFetchOptions): Promise<HttpFetchResult>;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export function resolveRedirect(
  status: number,
  locationHeader: string | undefined,
  currentUrl: string,
  expectedHostname: string,
): URL | null {
  if (!REDIRECT_STATUSES.has(status)) return null;
  if (!locationHeader) return null;
  const next = URL.parse(locationHeader, currentUrl);
  if (next === null || next.hostname !== expectedHostname) return null;
  return next;
}

export function parseHttpResponse(buf: Buffer, bodyLimit: number): HttpFetchResult | null {
  const headerEnd = buf.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;
  const headerText = buf.subarray(0, headerEnd).toString("ascii");
  const lines = headerText.split("\r\n");
  const statusLine = lines[0];
  if (!statusLine) return null;
  const statusMatch = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);
  if (!statusMatch?.[1]) return null;
  const status = parseInt(statusMatch[1], 10);
  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const k = line.slice(0, idx).trim().toLowerCase();
    const v = line.slice(idx + 1).trim();
    headers[k] = v;
  }
  const rest = buf.subarray(headerEnd + 4);
  const transferEncoding = headers["transfer-encoding"];
  const contentLengthStr = headers["content-length"];
  let body: Buffer;
  let truncated = false;
  if (transferEncoding && /chunked/i.test(transferEncoding)) {
    const decoded = decodeChunked(rest, bodyLimit);
    if (!decoded) return null;
    body = decoded.body;
    truncated = decoded.truncated;
  } else if (contentLengthStr) {
    const len = parseInt(contentLengthStr, 10);
    if (rest.length < len) return null;
    const cap = Math.min(len, bodyLimit);
    body = rest.subarray(0, cap);
    truncated = len > bodyLimit;
  } else {
    const cap = Math.min(rest.length, bodyLimit);
    body = rest.subarray(0, cap);
    truncated = rest.length > bodyLimit;
  }
  return { status, headers, body, truncated };
}

interface ChunkedResult {
  body: Buffer;
  truncated: boolean;
  complete: boolean;
}

function decodeChunked(buf: Buffer, bodyLimit: number): ChunkedResult | null {
  const parts: Buffer[] = [];
  let total = 0;
  let pos = 0;
  while (pos < buf.length) {
    const crlf = buf.indexOf("\r\n", pos);
    if (crlf === -1) return null;
    const sizeStr = buf.subarray(pos, crlf).toString("ascii").split(";")[0]?.trim() ?? "";
    const size = parseInt(sizeStr, 16);
    if (!Number.isFinite(size)) return null;
    pos = crlf + 2;
    if (size === 0) {
      return { body: Buffer.concat(parts, total), truncated: false, complete: true };
    }
    if (pos + size + 2 > buf.length) return null;
    const remaining = bodyLimit - total;
    if (remaining <= 0) {
      return { body: Buffer.concat(parts, total), truncated: true, complete: false };
    }
    const take = Math.min(size, remaining);
    parts.push(buf.subarray(pos, pos + take));
    total += take;
    pos += size + 2;
    if (take < size) {
      return { body: Buffer.concat(parts, total), truncated: true, complete: false };
    }
  }
  return null;
}

async function fetchOnce(opts: HttpFetchOptions): Promise<HttpFetchResult> {
  const port = opts.port ?? 443;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const bodyLimit = opts.bodyLimit ?? 1024 * 1024;
  const url = URL.parse(opts.url);
  if (url === null) throw new Error(`invalid URL: ${opts.url}`);
  const path = `${url.pathname || "/"}${url.search}`;

  const signal = AbortSignal.timeout(timeoutMs);
  const socket = tls.connect({
    host: opts.address,
    port,
    servername: opts.servername,
    rejectUnauthorized: false,
    ALPNProtocols: ["http/1.1"],
  });
  // On timeout the socket is destroyed with an AbortError, which ends the awaits below.
  addAbortSignal(signal, socket);

  const chunks: Buffer[] = [];
  let totalReceived = 0;
  // Enough for the headers plus `bodyLimit` bytes of body; stop reading after that.
  const maxBuffer = bodyLimit + 65536;
  try {
    await once(socket, "secureConnect");
    socket.write(
      `GET ${path} HTTP/1.1\r\nHost: ${opts.servername}\r\nUser-Agent: dns-checker\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
    );
    for await (const chunk of socket as AsyncIterable<Buffer>) {
      chunks.push(chunk);
      totalReceived += chunk.length;
      if (totalReceived >= maxBuffer) break;
    }
  } catch (err) {
    if (signal.aborted) throw new Error(`HTTP fetch timed out after ${timeoutMs}ms`);
    throw err;
  } finally {
    socket.destroy();
  }

  const parsed = parseHttpResponse(Buffer.concat(chunks, totalReceived), bodyLimit);
  if (!parsed) throw new Error("malformed HTTP response");
  return parsed;
}

export function createHttpTransport(): HttpTransport {
  return {
    async get(opts) {
      let current = opts;
      let budget = opts.maxRedirects ?? 5;
      for (;;) {
        const res = await fetchOnce(current);
        if (budget <= 0) return res;
        const next = resolveRedirect(
          res.status,
          res.headers["location"],
          current.url,
          current.servername,
        );
        if (!next) return res;
        budget -= 1;
        current = { ...current, url: next.toString(), maxRedirects: budget };
      }
    },
  };
}
