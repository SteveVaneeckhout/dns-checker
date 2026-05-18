# dns-checker

A TypeScript / Node.js library that runs seven DNS-related health checks against
a website's hostname:

1. Is IPv4 and IPv6 available?
2. Are the nameservers available over IPv4 and IPv6?
3. Is the website the same on IPv4 and IPv6?
4. Is the domain signed with DNSSEC?
5. Is the DNSSEC signature valid (local chain validation from the IANA root
   trust anchors — no resolver is trusted)?
6. Is there a CAA record and is it valid against the served certificate?
7. Is there a TLSA record and does the DANE fingerprint match the served
   certificate?

ESM only. Requires Node `>=24.15.0`.

## Install

```sh
npm install dns-checker
```

## Quick start

```ts
import { checkDomain } from "dns-checker";

const result = await checkDomain("example.com");
console.log(JSON.stringify(result, null, 2));
```

`checkDomain` runs all six independent checks in parallel and the DANE check
after DNSSEC has been evaluated (DANE requires a valid DNSSEC chain).

## API

### `checkDomain(host, options?, transports?)`

Runs every check. Returns:

```ts
interface CheckResult {
  hostname: string;
  startedAt: string; // ISO timestamp
  durationMs: number;
  ip: IpResult; // A/AAAA presence + TLS reachability
  nameservers: NameserverResult; // NS dual-stack reachability
  sameness: SamenessResult; // v4 vs v6 body similarity (200s) or hash equality (non-200s)
  dnssec: DnssecResult; // signed + chain validity + chain steps
  caa: CaaResult; // records + cert issuer match
  dane: DaneResult; // TLSA + cert match
}
```

Each individual check is also exported:

```ts
import {
  checkIp,
  checkNameservers,
  checkSameness,
  checkDnssec,
  checkCaa,
  checkDane,
} from "dns-checker";
```

### `CheckOptions`

```ts
interface CheckOptions {
  url?: string; // default: `https://${hostname}/`
  timeoutMs?: number; // per-query / per-socket timeout, default 5000
  resolver?: string; // recursive resolver IP, default "1.1.1.1"
  bodyHashLimit?: number; // cap response body bytes read for hashing/similarity, default 1 MiB
  trustAnchors?: readonly RootTrustAnchorRef[]; // override IANA roots (testing)
}
```

### `CheckTransports`

For tests or custom networking, the underlying transports can be injected:

```ts
import { checkDomain, type CheckTransports } from "dns-checker";

const transports: CheckTransports = {
  dns: myDnsTransport, // satisfies DnsTransport
  tls: myTlsTransport, // satisfies TlsTransport
  http: myHttpTransport, // satisfies HttpTransport
};

await checkDomain("example.com", undefined, transports);
```

## What each check actually does

| Check       | Wire calls                                                                                                                                                                                    |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ip          | Resolve A + AAAA, then TLS handshake to each on port 443 to confirm reachability.                                                                                                             |
| nameservers | Resolve NS for the apex, then SOA-probe each NS on UDP/53 over both v4 and v6.                                                                                                                |
| sameness    | Open TLS to first v4 and first v6 IP, send HTTP/1.1 GET; for 200s compare bodies with a Jaccard byte-shingle similarity, for other responses compare a SHA-256 of `status + Location + body`. |
| dnssec      | Walk root → … → apex with the DO bit set, verify every RRSIG locally with `node:crypto`.                                                                                                      |
| caa         | Tree-walk CAA per RFC 8659, fetch the leaf cert, match issuer against the CAA tag.                                                                                                            |
| dane        | Query TLSA at `_443._tcp.<host>`, verify with DNSSEC, match against the served cert.                                                                                                          |

### Sameness

The sameness check compares what the IPv4 and IPv6 endpoints serve at the same
URL. Behavior depends on the HTTP status code of the two responses:

- **Both responses are 200**: the bodies are compared with a Jaccard similarity
  over rolling 8-byte shingles. The result is exposed as `similarity` in the
  `[0, 1]` range (1 = identical, 0 = no overlap). `ipv4Hash` / `ipv6Hash` are
  not set, and `match` is `false` — the library deliberately does not pick a
  pass/fail threshold; callers decide what counts as "the same enough".
- **Anything else** (redirects, errors, mixed status codes): each side is
  fingerprinted with `SHA-256(status + "\n" + Location + "\n" + body)`. The
  hashes are exposed as `ipv4Hash` / `ipv6Hash`; `match` is `true` when they
  are equal.

`ok` means the check ran without errors (DNS + both fetches succeeded). It does
**not** imply the responses matched — read `similarity` (200 case) or `match`
(non-200 case) for that.

### DNSSEC

The library performs **local** DNSSEC chain validation: it queries DNSKEY, DS,
and RRSIG records via the configured recursive resolver, then verifies each
signature against the parent zone's DNSKEY using Node's crypto primitives. The
root key is anchored against the published IANA trust anchors (KSK-2017 and
KSK-2024). The resolver is **not** trusted to set the AD flag.

Supported DNSKEY algorithms: 8 (RSA/SHA-256), 10 (RSA/SHA-512),
13 (ECDSA P-256/SHA-256), 14 (ECDSA P-384/SHA-384), 15 (Ed25519).
Older algorithms (5/7 RSA/SHA-1) are explicitly not supported.

### CAA

The check maps a small set of well-known CA tags (`letsencrypt.org`,
`digicert.com`, `sectigo.com`, `globalsign.com`, `godaddy.com`, `pki.goog`,
`amazon(trust).com`, `buypass.com`, `entrust.net`, `ssl.com`, `certum.pl`, etc.)
to issuer-organization substrings and looks for a match. **Unknown CA tags
produce a clear error rather than silently passing** — that way a CAA policy
referring to a CA the library doesn't know about is surfaced as a configuration
warning, not silently treated as success.

## Limitations / non-goals (v1)

- The IPv4/IPv6 reachability probe uses a TLS handshake on 443. Hostnames that
  only serve plaintext HTTP report unreachable.
- The sameness check does not follow redirects. A redirect to a different host
  would make the comparison meaningless, so the v4/v6 comparison is always
  performed at the configured URL exactly.
- DNSSEC validates only modern algorithms (8, 10, 13, 14, 15). Zones using
  RSA/SHA-1 (algorithms 5/7) are reported as unsupported.
- CAA tag matching uses a built-in table of common CAs. PRs welcome to extend.

## Manual verification

These domains are useful for poking at the library by hand. They are intentionally
not used in the test suite (which mocks all transports):

| Domain                | Exercises                                         |
| --------------------- | ------------------------------------------------- |
| `internet.nl`         | Dual-stack, DNSSEC, CAA — a real production site. |
| `internetsociety.org` | Has TLSA records — exercises DANE happy path.     |
| `dnssec-failed.org`   | Intentionally broken DNSSEC.                      |

```ts
import { checkDomain } from "dns-checker";

const r = await checkDomain("internet.nl");
console.dir(r, { depth: null });
```

## Scripts

- `npm run build` — compile to `dist/`.
- `npm test` — run vitest.
- `npm run test:coverage` — coverage report. Thresholds are set at a pragmatic
  level (80/75/80/80) because the transport layer is hard to unit-test without
  real network services; the core logic in `src/checks/` and `src/dnssec/` is
  covered ≥95%.
- `npm run typecheck` — `tsc --noEmit`.
- `npm run fmt` / `fmt:check` — oxfmt.

## License

MIT — see `LICENSE`.
