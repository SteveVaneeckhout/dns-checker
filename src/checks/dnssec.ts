import { validateChain } from "../dnssec/chain.js";
import { ROOT_TRUST_ANCHORS } from "../dnssec/rootKeys.js";
import type { DnsTransport } from "../net/dns.js";
import type { DnssecResult, ResolvedOptions } from "../types.js";

export async function runDnssecCheck(
  hostname: string,
  opts: ResolvedOptions,
  dns: DnsTransport,
): Promise<DnssecResult> {
  const anchors = opts.trustAnchors ?? ROOT_TRUST_ANCHORS;
  const result = await validateChain(hostname, dns, anchors);
  return {
    ok: result.chainValid,
    errors: result.errors,
    signed: result.signed,
    chainValid: result.chainValid,
    chain: result.chain.map((s) => ({
      zone: s.zone,
      dsVerified: s.dsVerified,
      keysVerified: s.keysVerified,
    })),
  };
}
