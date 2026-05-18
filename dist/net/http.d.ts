import { Buffer } from "node:buffer";
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
export declare function resolveRedirect(status: number, locationHeader: string | undefined, currentUrl: string, expectedHostname: string): URL | null;
export declare function parseHttpResponse(buf: Buffer, bodyLimit: number): HttpFetchResult | null;
export declare function createHttpTransport(): HttpTransport;
