import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Answer, CaaData, DnskeyData, DsData, RrsigData, SoaData, TlsaData } from "dns-packet";

const TYPE_NUMBERS: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  TLSA: 52,
  SPF: 99,
  CAA: 257,
};

export function typeNumber(name: string): number {
  const n = TYPE_NUMBERS[name.toUpperCase()];
  if (n === undefined) throw new Error(`unknown RR type: ${name}`);
  return n;
}

export function encodeName(name: string): Buffer {
  const trimmed = name.replace(/\.$/, "");
  if (trimmed === "") return Buffer.from([0]);
  const labels = trimmed.split(".");
  const parts: Buffer[] = [];
  for (const label of labels) {
    const lower = label.toLowerCase();
    const buf = Buffer.from(lower, "utf8");
    if (buf.length === 0 || buf.length > 63) {
      throw new Error(`invalid label: '${label}'`);
    }
    parts.push(Buffer.from([buf.length]), buf);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

export function encodeIPv4(addr: string): Buffer {
  const parts = addr.split(".");
  if (parts.length !== 4) throw new Error(`invalid IPv4: ${addr}`);
  const out = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    const v = parseInt(parts[i] ?? "", 10);
    if (!Number.isFinite(v) || v < 0 || v > 255) throw new Error(`invalid IPv4: ${addr}`);
    out[i] = v;
  }
  return out;
}

export function encodeIPv6(addr: string): Buffer {
  let parts: string[];
  if (addr.includes("::")) {
    const [head, tail] = addr.split("::") as [string, string];
    const h = head ? head.split(":") : [];
    const t = tail ? tail.split(":") : [];
    const missing = 8 - h.length - t.length;
    if (missing < 0) throw new Error(`invalid IPv6: ${addr}`);
    parts = [...h, ...Array<string>(missing).fill("0"), ...t];
  } else {
    parts = addr.split(":");
  }
  if (parts.length !== 8) throw new Error(`invalid IPv6: ${addr}`);
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const v = parseInt(parts[i] ?? "0", 16);
    if (!Number.isFinite(v) || v < 0 || v > 0xffff) throw new Error(`invalid IPv6: ${addr}`);
    out.writeUInt16BE(v, i * 2);
  }
  return out;
}

function encodeUint16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}

function encodeUint32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

export function encodeDnskeyRdata(d: DnskeyData): Buffer {
  return Buffer.concat([encodeUint16(d.flags), Buffer.from([3, d.algorithm]), d.key]);
}

export function encodeDsRdata(d: DsData): Buffer {
  return Buffer.concat([
    encodeUint16(d.keyTag),
    Buffer.from([d.algorithm, d.digestType]),
    d.digest,
  ]);
}

export function encodeTlsaRdata(d: TlsaData): Buffer {
  return Buffer.concat([Buffer.from([d.usage, d.selector, d.matchingType]), d.certificate]);
}

export function encodeCaaRdata(d: CaaData): Buffer {
  const tag = Buffer.from(d.tag, "ascii");
  const value = Buffer.from(d.value, "utf8");
  const flags = d.flags ?? (d.issuerCritical ? 128 : 0);
  return Buffer.concat([Buffer.from([flags, tag.length]), tag, value]);
}

export function encodeSoaRdata(d: SoaData): Buffer {
  return Buffer.concat([
    encodeName(d.mname),
    encodeName(d.rname),
    encodeUint32(d.serial ?? 0),
    encodeUint32(d.refresh ?? 0),
    encodeUint32(d.retry ?? 0),
    encodeUint32(d.expire ?? 0),
    encodeUint32(d.minimum ?? 0),
  ]);
}

export function encodeRrsigRdataForSigning(r: RrsigData): Buffer {
  return Buffer.concat([
    encodeUint16(typeNumber(r.typeCovered)),
    Buffer.from([r.algorithm, r.labels]),
    encodeUint32(r.originalTTL),
    encodeUint32(r.expiration),
    encodeUint32(r.inception),
    encodeUint16(r.keyTag),
    encodeName(r.signersName),
  ]);
}

export function encodeRdata(answer: Answer): Buffer {
  switch (answer.type) {
    case "A":
      return encodeIPv4(answer.data);
    case "AAAA":
      return encodeIPv6(answer.data);
    case "NS":
    case "CNAME":
    case "PTR":
      return encodeName(answer.data);
    case "DNSKEY":
      return encodeDnskeyRdata(answer.data);
    case "DS":
      return encodeDsRdata(answer.data);
    case "TLSA":
      return encodeTlsaRdata(answer.data);
    case "CAA":
      return encodeCaaRdata(answer.data);
    case "SOA":
      return encodeSoaRdata(answer.data);
    default:
      throw new Error(`canonical RDATA for type ${answer.type} not implemented`);
  }
}

export function encodeRrForSigning(rrset: Answer[], rrsig: RrsigData): Buffer {
  if (rrset.length === 0) throw new Error("cannot sign empty RRset");
  const ownerName = rrset[0]?.name;
  if (ownerName === undefined) throw new Error("RRset missing name");
  const rdatas = rrset.map((r) => encodeRdata(r));
  rdatas.sort(Buffer.compare);
  const typeBuf = encodeUint16(typeNumber(rrset[0]?.type ?? ""));
  const classBuf = encodeUint16(1);
  const ttlBuf = encodeUint32(rrsig.originalTTL);
  const ownerBuf = encodeName(ownerName);
  const parts: Buffer[] = [];
  for (const rd of rdatas) {
    parts.push(ownerBuf, typeBuf, classBuf, ttlBuf, encodeUint16(rd.length), rd);
  }
  return Buffer.concat(parts);
}

export function rrsigSigningInput(rrsig: RrsigData, rrset: Answer[]): Buffer {
  return Buffer.concat([encodeRrsigRdataForSigning(rrsig), encodeRrForSigning(rrset, rrsig)]);
}

export function computeKeyTag(dnskey: DnskeyData): number {
  const rdata = encodeDnskeyRdata(dnskey);
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    ac += (i & 1) === 1 ? (rdata[i] ?? 0) : (rdata[i] ?? 0) << 8;
  }
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

export function computeDsDigest(ownerName: string, dnskey: DnskeyData, digestType: number): Buffer {
  const input = Buffer.concat([encodeName(ownerName), encodeDnskeyRdata(dnskey)]);
  if (digestType === 1) return createHash("sha1").update(input).digest();
  if (digestType === 2) return createHash("sha256").update(input).digest();
  if (digestType === 4) return createHash("sha384").update(input).digest();
  throw new Error(`unsupported DS digest type: ${digestType}`);
}
