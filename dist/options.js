export function resolveOptions(hostname, opts) {
    const base = {
        url: opts?.url ?? `https://${hostname}/`,
        timeoutMs: opts?.timeoutMs ?? 5000,
        resolver: opts?.resolver ?? "1.1.1.1",
        bodyHashLimit: opts?.bodyHashLimit ?? 1024 * 1024,
    };
    if (opts?.trustAnchors)
        base.trustAnchors = opts.trustAnchors;
    if (opts?.canonicalUrl !== undefined) {
        const canonical = URL.parse(opts.canonicalUrl);
        if (canonical === null)
            throw new Error(`invalid canonicalUrl: ${opts.canonicalUrl}`);
        base.canonicalUrl = canonical.href;
    }
    return base;
}
export function normalizeHostname(host) {
    const trimmed = host.trim().toLowerCase();
    if (trimmed.length === 0) {
        throw new Error("hostname is empty");
    }
    return trimmed.endsWith(".") ? trimmed.slice(0, -1) : trimmed;
}
