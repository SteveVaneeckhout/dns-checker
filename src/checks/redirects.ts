import type { DnsTransport } from "../net/dns.js";
import { REDIRECT_STATUSES, type HttpFetchResult, type HttpTransport } from "../net/http.js";
import { stringRecords } from "../net/records.js";
import type {
  RedirectChain,
  RedirectFamilyResult,
  RedirectHop,
  RedirectResult,
  ResolvedOptions,
} from "../types.js";
import { errorMessage } from "../util/errors.js";

/** Most responses fetched per chain; the start URL plus up to 9 redirects. */
const MAX_HOPS = 10;

/** Redirects that tell search engines and browsers the move is not permanent. */
const TEMPORARY_STATUSES: ReadonlySet<number> = new Set([302, 303, 307]);

type Family = { label: "IPv4"; type: "A" } | { label: "IPv6"; type: "AAAA" };
const IPV4: Family = { label: "IPv4", type: "A" };
const IPV6: Family = { label: "IPv6", type: "AAAA" };

interface Lookup {
  address?: string;
  error?: string;
  /** The query itself failed, as opposed to returning no address. */
  failed?: true;
}

/** `example.com` and `www.example.com`, whichever of the two `hostname` is. */
export function apexAndWww(hostname: string): { apex: string; www: string } {
  return hostname.startsWith("www.")
    ? { apex: hostname.slice(4), www: hostname }
    : { apex: hostname, www: `www.${hostname}` };
}

/** The four entry points: http/https × apex/www. */
export function startUrls(apex: string, www: string): string[] {
  return [`http://${apex}/`, `http://${www}/`, `https://${apex}/`, `https://${www}/`];
}

function isSuccess(status: number | undefined): boolean {
  return status !== undefined && status >= 200 && status < 300;
}

function createResolver(dns: DnsTransport, family: Family): (host: string) => Promise<Lookup> {
  const cache = new Map<string, Promise<Lookup>>();
  return (host) => {
    let lookup = cache.get(host);
    if (lookup === undefined) {
      lookup = stringRecords(dns, family.type, host).then(
        (addresses): Lookup => {
          const address = addresses[0];
          return address !== undefined
            ? { address }
            : { error: `no ${family.label} address for ${host}` };
        },
        (e: unknown): Lookup => ({
          error: `${family.type} lookup for ${host}: ${errorMessage(e)}`,
          failed: true,
        }),
      );
      cache.set(host, lookup);
    }
    return lookup;
  };
}

/** Requests `startUrl` and follows every redirect by hand, also across hosts. */
async function followChain(
  startUrl: string,
  resolve: (host: string) => Promise<Lookup>,
  http: HttpTransport,
  opts: ResolvedOptions,
): Promise<RedirectChain> {
  const chain: RedirectChain = { startUrl, hops: [], errors: [], warnings: [] };
  const seen = new Set<string>();
  let url = startUrl;
  for (;;) {
    if (seen.has(url)) {
      chain.errors.push(`${startUrl} loops: ${url} was already requested`);
      return chain;
    }
    if (seen.size >= MAX_HOPS) {
      chain.errors.push(`${startUrl} takes more than ${MAX_HOPS - 1} redirects`);
      return chain;
    }
    seen.add(url);

    const host = new URL(url).hostname;
    const lookup = await resolve(host);
    if (lookup.address === undefined) {
      chain.errors.push(lookup.error ?? `no address for ${host}`);
      return chain;
    }
    let res: HttpFetchResult;
    try {
      res = await http.get({
        address: lookup.address,
        servername: host,
        url,
        timeoutMs: opts.timeoutMs,
        bodyLimit: opts.bodyHashLimit,
        maxRedirects: 0,
      });
    } catch (e) {
      chain.errors.push(`${url}: ${errorMessage(e)}`);
      return chain;
    }

    const hop: RedirectHop = { url, address: lookup.address, status: res.status };
    const location = res.headers["location"];
    if (location !== undefined) hop.location = location;
    chain.hops.push(hop);
    chain.finalUrl = url;
    chain.finalStatus = res.status;

    if (!REDIRECT_STATUSES.has(res.status)) return chain;
    if (location === undefined || location === "") {
      chain.errors.push(`${url}: ${res.status} without a Location header`);
      return chain;
    }
    const next = URL.parse(location, url);
    if (next === null || (next.protocol !== "http:" && next.protocol !== "https:")) {
      chain.errors.push(`${url}: invalid Location header: ${location}`);
      return chain;
    }
    url = next.href;
  }
}

/**
 * Adds the errors and warnings that depend on the redirects taken and the canonical origin.
 * Only moves to another scheme or host are judged; a redirect within one origin, such as a
 * language redirect from `/` to `/en/`, is the site's own business.
 */
function judgeChain(chain: RedirectChain, canonicalOrigin: string | undefined): void {
  const followed = chain.errors.length === 0;
  for (const [i, hop] of chain.hops.entries()) {
    const next = chain.hops[i + 1];
    if (next === undefined) break;
    const sameOrigin = new URL(hop.url).origin === new URL(next.url).origin;
    if (TEMPORARY_STATUSES.has(hop.status) && !sameOrigin) {
      chain.errors.push(
        `${hop.url} redirects with a temporary ${hop.status}; use 301 or 308 for a permanent move`,
      );
    }
    if (hop.url.startsWith("https:") && next.url.startsWith("http:")) {
      chain.errors.push(`${hop.url} redirects from HTTPS to HTTP (${next.url})`);
    }
  }

  const start = new URL(chain.startUrl);
  const first = chain.hops[0];
  const second = chain.hops[1];
  if (start.protocol === "http:" && first !== undefined && second !== undefined) {
    const target = new URL(second.url);
    if (target.protocol !== "https:" || target.hostname !== start.hostname) {
      chain.warnings.push(
        `${chain.startUrl} first redirects to ${second.url}; redirect to https://${start.hostname}/ first so browsers get the HSTS header for ${start.hostname} (required for HSTS preload)`,
      );
    }
  }

  if (!followed) return;
  if (!isSuccess(chain.finalStatus)) {
    chain.errors.push(`${chain.finalUrl} answers HTTP ${chain.finalStatus}`);
  } else if (
    canonicalOrigin !== undefined &&
    chain.finalUrl !== undefined &&
    new URL(chain.finalUrl).origin !== canonicalOrigin
  ) {
    chain.errors.push(`${chain.startUrl} ends at ${chain.finalUrl}, not on ${canonicalOrigin}`);
  }
}

/** Distinct messages in first-seen order, each with the families that reported it. */
class MessageList {
  readonly #families = new Map<string, Set<string>>();

  add(message: string, family: string): void {
    const families = this.#families.get(message) ?? new Set<string>();
    families.add(family);
    this.#families.set(message, families);
  }

  /** `[IPv4, IPv6] message` per distinct message. */
  lines(): string[] {
    return [...this.#families].map(
      ([message, families]) => `[${[...families].join(", ")}] ${message}`,
    );
  }
}

/** The origin most successful chains end on; ties prefer HTTPS, then the earlier chain. */
function pickCanonical(chains: readonly RedirectChain[]): string | undefined {
  const counts = new Map<string, number>();
  for (const chain of chains) {
    if (chain.errors.length > 0 || !isSuccess(chain.finalStatus) || chain.finalUrl === undefined) {
      continue;
    }
    const origin = new URL(chain.finalUrl).origin;
    counts.set(origin, (counts.get(origin) ?? 0) + 1);
  }
  let best: string | undefined;
  let bestScore = -1;
  for (const [origin, count] of counts) {
    const score = count * 2 + (origin.startsWith("https:") ? 1 : 0);
    if (score > bestScore) {
      best = origin;
      bestScore = score;
    }
  }
  return best;
}

async function runFamily(
  family: Family,
  urls: readonly string[],
  apex: string,
  www: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  http: HttpTransport,
  errors: string[],
): Promise<RedirectFamilyResult> {
  const resolve = createResolver(dns, family);
  const [apexLookup, wwwLookup] = await Promise.all([resolve(apex), resolve(www)]);
  if (apexLookup.address === undefined && wwwLookup.address === undefined) {
    // A missing family is the ip check's finding; only a failed lookup is an error here.
    for (const lookup of [apexLookup, wwwLookup]) {
      if (lookup.failed && lookup.error !== undefined) errors.push(lookup.error);
    }
    return { available: false, chains: [] };
  }
  const chains = await Promise.all(urls.map((url) => followChain(url, resolve, http, opts)));
  return { available: true, chains };
}

export async function runRedirectCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
  http: HttpTransport,
): Promise<RedirectResult> {
  const { apex, www } = apexAndWww(hostname);
  const urls = startUrls(apex, www);
  const errors: string[] = [];
  const warnings: string[] = [];
  const [ipv4, ipv6] = await Promise.all([
    runFamily(IPV4, urls, apex, www, opts, dns, http, errors),
    runFamily(IPV6, urls, apex, www, opts, dns, http, errors),
  ]);

  const result: RedirectResult = { ok: false, errors, warnings, apex, www, ipv4, ipv6 };
  if (!ipv4.available && !ipv6.available) {
    errors.push(`no IPv4 or IPv6 address for ${apex} or ${www}`);
    return result;
  }

  const canonicalOrigin = opts.canonicalOrigin ?? pickCanonical([...ipv4.chains, ...ipv6.chains]);
  if (canonicalOrigin !== undefined) {
    result.canonicalOrigin = canonicalOrigin;
    if (!canonicalOrigin.startsWith("https:")) {
      errors.push(`canonical origin ${canonicalOrigin} is not HTTPS`);
    }
  }

  // Several chains often pass the same hop, and IPv4 and IPv6 usually behave alike, so the
  // same message comes up more than once. Each message names the URL it is about, so list it
  // once with the families that saw it.
  const chainErrors = new MessageList();
  const chainWarnings = new MessageList();
  for (const [family, label] of [
    [ipv4, "IPv4"],
    [ipv6, "IPv6"],
  ] as const) {
    for (const chain of family.chains) {
      judgeChain(chain, canonicalOrigin);
      for (const e of chain.errors) chainErrors.add(e, label);
      for (const w of chain.warnings) chainWarnings.add(w, label);
    }
  }
  errors.push(...chainErrors.lines());
  warnings.push(...chainWarnings.lines());

  result.ok = errors.length === 0;
  return result;
}
