import type { TLSSocket, PeerCertificate, DetailedPeerCertificate } from "node:tls";
export interface TlsHandshakeOptions {
    address: string;
    port?: number;
    servername: string;
    timeoutMs?: number;
    rejectUnauthorized?: boolean;
}
export interface TlsHandshakeResult {
    authorized: boolean;
    authorizationError?: string;
    leaf: DetailedPeerCertificate;
    chain: DetailedPeerCertificate[];
    socket: TLSSocket;
}
export interface TlsTransport {
    handshake(opts: TlsHandshakeOptions): Promise<TlsHandshakeResult>;
}
export declare function collectChain(leaf: DetailedPeerCertificate): DetailedPeerCertificate[];
export declare function createTlsTransport(): TlsTransport;
export declare function certIssuerString(cert: PeerCertificate): string;
export declare function certSubjectCN(cert: PeerCertificate): string;
export declare function certSubjectAltNames(cert: PeerCertificate): string[];
