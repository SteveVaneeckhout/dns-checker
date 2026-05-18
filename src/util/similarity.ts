import { Buffer } from "node:buffer";

const DEFAULT_K = 8;
const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

function hashShingle(buf: Buffer, start: number, end: number): number {
  let h1 = FNV_OFFSET;
  let h2 = 0x84222325;
  for (let i = start; i < end; i++) {
    const byte = buf[i] as number;
    h1 = Math.imul(h1 ^ byte, FNV_PRIME) >>> 0;
    h2 = Math.imul(h2 ^ byte, 0x1000193) >>> 0;
  }
  return h1 * 0x100000 + (h2 & 0xfffff);
}

function shingleSet(buf: Buffer, k: number): Set<number> {
  const set = new Set<number>();
  if (buf.length === 0) return set;
  if (buf.length < k) {
    set.add(hashShingle(buf, 0, buf.length));
    return set;
  }
  for (let i = 0; i <= buf.length - k; i++) {
    set.add(hashShingle(buf, i, i + k));
  }
  return set;
}

export function jaccardShingleSimilarity(a: Buffer, b: Buffer, k: number = DEFAULT_K): number {
  if (a.length === 0 && b.length === 0) return 1;
  if (a.length === 0 || b.length === 0) return 0;
  const setA = shingleSet(a, k);
  const setB = shingleSet(b, k);
  let intersection = 0;
  const [small, large] = setA.size <= setB.size ? [setA, setB] : [setB, setA];
  for (const v of small) {
    if (large.has(v)) intersection++;
  }
  const union = setA.size + setB.size - intersection;
  return union === 0 ? 1 : intersection / union;
}
