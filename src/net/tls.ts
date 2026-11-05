import { once } from "node:events";
import tls from "node:tls";
import type { TLSSocket, PeerCertificate, DetailedPeerCertificate } from "node:tls";

export interface TlsHandshakeOptions {
  address: string;
  port?: number;
  servername: string;
  timeoutMs?: number;
  rejectUnauthorized?: boolean;
}

/**
 * A completed handshake. The socket stays open so callers can inspect it; dispose the
 * result (`using r = await tls.handshake(...)`) to close it.
 */
export interface TlsHandshakeResult extends Disposable {
  authorized: boolean;
  authorizationError?: string;
  leaf: DetailedPeerCertificate;
  chain: DetailedPeerCertificate[];
  socket: TLSSocket;
}

export interface TlsTransport {
  handshake(opts: TlsHandshakeOptions): Promise<TlsHandshakeResult>;
}

export function collectChain(leaf: DetailedPeerCertificate): DetailedPeerCertificate[] {
  const chain: DetailedPeerCertificate[] = [];
  const seen = new Set<DetailedPeerCertificate>();
  let cur: DetailedPeerCertificate | undefined = leaf;
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    chain.push(cur);
    const parent: DetailedPeerCertificate | undefined = cur.issuerCertificate;
    if (!parent || parent === cur) break;
    cur = parent;
  }
  return chain;
}

export function createTlsTransport(): TlsTransport {
  return {
    async handshake(opts) {
      const port = opts.port ?? 443;
      const timeoutMs = opts.timeoutMs ?? 5000;
      const signal = AbortSignal.timeout(timeoutMs);
      const socket = tls.connect({
        host: opts.address,
        port,
        servername: opts.servername,
        rejectUnauthorized: opts.rejectUnauthorized ?? false,
        ALPNProtocols: ["http/1.1"],
      });
      try {
        await once(socket, "secureConnect", { signal });
      } catch (err) {
        socket.destroy();
        if (signal.aborted) throw new Error(`TLS handshake timed out after ${timeoutMs}ms`);
        throw err;
      }
      // The socket outlives this call; keep a late reset from becoming an uncaught "error".
      socket.on("error", () => {});
      const leaf = socket.getPeerCertificate(true) as DetailedPeerCertificate;
      if (!leaf || Object.keys(leaf).length === 0) {
        socket.destroy();
        throw new Error("no peer certificate");
      }
      const result: TlsHandshakeResult = {
        authorized: socket.authorized,
        leaf,
        chain: collectChain(leaf),
        socket,
        [Symbol.dispose]() {
          socket.destroy();
        },
      };
      if (socket.authorizationError) {
        result.authorizationError = String(socket.authorizationError);
      }
      return result;
    },
  };
}

function asString(v: string | string[] | undefined): string | undefined {
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v[0];
  return v;
}

export function certIssuerString(cert: PeerCertificate): string {
  const issuer = cert.issuer;
  if (!issuer) return "";
  const parts: string[] = [];
  const o = asString(issuer.O);
  const cn = asString(issuer.CN);
  if (o) parts.push(`O=${o}`);
  if (cn) parts.push(`CN=${cn}`);
  return parts.join(", ");
}

export function certSubjectCN(cert: PeerCertificate): string {
  return asString(cert.subject?.CN) ?? "";
}

export function certSubjectAltNames(cert: PeerCertificate): string[] {
  const san = cert.subjectaltname;
  if (!san) return [];
  return san
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:"))
    .map((s) => s.slice(4).toLowerCase());
}
