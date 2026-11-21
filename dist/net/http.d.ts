import { Buffer } from "node:buffer";
export interface HttpFetchOptions {
    address: string;
    /** Defaults to the port in `url`, else 443 for `https:` and 80 for `http:`. */
    port?: number;
    servername: string;
    url: string;
    timeoutMs?: number;
    bodyLimit?: number;
    /** Same-host redirects to follow; 0 returns the first response as is. Default 5. */
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
export declare const REDIRECT_STATUSES: ReadonlySet<number>;
export declare function resolveRedirect(status: number, locationHeader: string | undefined, currentUrl: string, expectedHostname: string): URL | null;
export declare function parseHttpResponse(buf: Buffer, bodyLimit: number): HttpFetchResult | null;
export declare function createHttpTransport(): HttpTransport;
