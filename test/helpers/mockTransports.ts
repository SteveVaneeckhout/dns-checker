import { Buffer } from "node:buffer";
import type { Answer, DecodedPacket } from "dns-packet";
import type { DnsQueryOptions, DnsTransport } from "../../src/net/dns.ts";
import type { HttpFetchOptions, HttpFetchResult, HttpTransport } from "../../src/net/http.ts";
import type { TlsHandshakeOptions, TlsHandshakeResult, TlsTransport } from "../../src/net/tls.ts";
import type { DetailedPeerCertificate, TLSSocket } from "node:tls";

export function packetWith(answers: Answer[] = []): DecodedPacket {
  return {
    type: "response",
    flag_qr: true,
    flag_aa: false,
    flag_tc: false,
    flag_rd: true,
    flag_ra: true,
    flag_z: false,
    flag_ad: false,
    flag_cd: false,
    questions: [],
    answers,
    authorities: [],
    additionals: [],
  } as DecodedPacket;
}

export type DnsHandler = (opts: DnsQueryOptions) => DecodedPacket | Promise<DecodedPacket>;

export function mockDns(handler: DnsHandler): DnsTransport {
  return {
    async query(opts) {
      return handler(opts);
    },
  };
}

export type TlsHandler = (
  opts: TlsHandshakeOptions,
) => TlsHandshakeResult | Promise<TlsHandshakeResult>;

export function mockTls(handler: TlsHandler): TlsTransport {
  return {
    async handshake(opts) {
      return handler(opts);
    },
  };
}

export type HttpHandler = (opts: HttpFetchOptions) => HttpFetchResult | Promise<HttpFetchResult>;

export function mockHttp(handler: HttpHandler): HttpTransport {
  return {
    async get(opts) {
      return handler(opts);
    },
  };
}

export interface FakeCertOptions {
  issuerCN?: string;
  issuerO?: string;
  subjectCN?: string;
  raw?: Buffer;
  pubkey?: Buffer;
  san?: string;
}

export function fakeCert(opts: FakeCertOptions = {}): DetailedPeerCertificate {
  const cert = {
    subject: { CN: opts.subjectCN ?? "host.test", C: "", ST: "", L: "", O: "", OU: "" },
    issuer: {
      CN: opts.issuerCN ?? "Let's Encrypt R3",
      O: opts.issuerO ?? "Let's Encrypt",
      C: "",
      ST: "",
      L: "",
      OU: "",
    },
    raw: opts.raw ?? Buffer.from([0xaa, 0xbb]),
    pubkey: opts.pubkey ?? Buffer.from([0xcc, 0xdd]),
    subjectaltname: opts.san ?? `DNS:${opts.subjectCN ?? "host.test"}`,
    valid_from: "",
    valid_to: "",
    fingerprint: "",
    fingerprint256: "",
    fingerprint512: "",
    ext_key_usage: [],
    serialNumber: "",
    bits: 0,
    asn1Curve: "",
    nistCurve: "",
    modulus: "",
    exponent: "",
  } as unknown as DetailedPeerCertificate;
  (cert as { issuerCertificate?: DetailedPeerCertificate }).issuerCertificate = cert;
  return cert;
}

export function fakeHandshake(
  cert: DetailedPeerCertificate,
  chain: DetailedPeerCertificate[] = [cert],
): TlsHandshakeResult {
  const noopSocket = {
    destroy: () => undefined,
  } as unknown as TLSSocket;
  return {
    authorized: true,
    leaf: cert,
    chain,
    socket: noopSocket,
  };
}
