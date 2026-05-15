import tls from "node:tls";
import { Buffer } from "node:buffer";
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
export function resolveRedirect(status, locationHeader, currentUrl, expectedHostname) {
  if (!REDIRECT_STATUSES.has(status)) return null;
  if (!locationHeader) return null;
  let next;
  try {
    next = new URL(locationHeader, currentUrl);
  } catch {
    return null;
  }
  if (next.hostname !== expectedHostname) return null;
  return next;
}
export function parseHttpResponse(buf, bodyLimit) {
  const headerEnd = buf.indexOf("\r\n\r\n");
  if (headerEnd === -1) return null;
  const headerText = buf.subarray(0, headerEnd).toString("ascii");
  const lines = headerText.split("\r\n");
  const statusLine = lines[0];
  if (!statusLine) return null;
  const statusMatch = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);
  if (!statusMatch?.[1]) return null;
  const status = parseInt(statusMatch[1], 10);
  const headers = {};
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
  let body;
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
function decodeChunked(buf, bodyLimit) {
  const parts = [];
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
function fetchOnce(opts) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const port = opts.port ?? 443;
    const timeoutMs = opts.timeoutMs ?? 5000;
    const bodyLimit = opts.bodyLimit ?? 1024 * 1024;
    let url;
    try {
      url = new URL(opts.url);
    } catch {
      reject(new Error(`invalid URL: ${opts.url}`));
      return;
    }
    const path = `${url.pathname || "/"}${url.search}`;
    const socket = tls.connect({
      host: opts.address,
      port,
      servername: opts.servername,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
    });
    const chunks = [];
    let totalReceived = 0;
    const maxBuffer = bodyLimit + 65536;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`HTTP fetch timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const finish = (buf) => {
      const parsed = parseHttpResponse(buf, bodyLimit);
      if (!parsed) {
        reject(new Error("malformed HTTP response"));
        return;
      }
      resolve(parsed);
    };
    socket.once("secureConnect", () => {
      const req = `GET ${path} HTTP/1.1\r\nHost: ${opts.servername}\r\nUser-Agent: dns-checker\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
      socket.write(req);
    });
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      totalReceived += chunk.length;
      if (totalReceived >= maxBuffer) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        finish(Buffer.concat(chunks));
      }
    });
    socket.once("end", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      finish(Buffer.concat(chunks));
    });
    socket.once("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    });
  });
}
export function createHttpTransport() {
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
