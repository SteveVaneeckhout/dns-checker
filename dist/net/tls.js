import { once } from "node:events";
import tls from "node:tls";
export function collectChain(leaf) {
    const chain = [];
    const seen = new Set();
    let cur = leaf;
    while (cur && !seen.has(cur)) {
        seen.add(cur);
        chain.push(cur);
        const parent = cur.issuerCertificate;
        if (!parent || parent === cur)
            break;
        cur = parent;
    }
    return chain;
}
export function createTlsTransport() {
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
            }
            catch (err) {
                socket.destroy();
                if (signal.aborted)
                    throw new Error(`TLS handshake timed out after ${timeoutMs}ms`);
                throw err;
            }
            // The socket outlives this call; keep a late reset from becoming an uncaught "error".
            socket.on("error", () => { });
            const leaf = socket.getPeerCertificate(true);
            if (!leaf || Object.keys(leaf).length === 0) {
                socket.destroy();
                throw new Error("no peer certificate");
            }
            const result = {
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
function asString(v) {
    if (v === undefined)
        return undefined;
    if (Array.isArray(v))
        return v[0];
    return v;
}
export function certIssuerString(cert) {
    const issuer = cert.issuer;
    if (!issuer)
        return "";
    const parts = [];
    const o = asString(issuer.O);
    const cn = asString(issuer.CN);
    if (o)
        parts.push(`O=${o}`);
    if (cn)
        parts.push(`CN=${cn}`);
    return parts.join(", ");
}
export function certSubjectCN(cert) {
    return asString(cert.subject?.CN) ?? "";
}
export function certSubjectAltNames(cert) {
    const san = cert.subjectaltname;
    if (!san)
        return [];
    return san
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.startsWith("DNS:"))
        .map((s) => s.slice(4).toLowerCase());
}
