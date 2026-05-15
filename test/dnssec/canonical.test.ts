import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  computeDsDigest,
  computeKeyTag,
  encodeCaaRdata,
  encodeDnskeyRdata,
  encodeDsRdata,
  encodeIPv4,
  encodeIPv6,
  encodeName,
  encodeRdata,
  encodeRrForSigning,
  encodeRrsigRdataForSigning,
  encodeSoaRdata,
  encodeTlsaRdata,
  rrsigSigningInput,
  typeNumber,
} from "../../src/dnssec/canonical.ts";

describe("typeNumber", () => {
  it("maps standard types", () => {
    expect(typeNumber("A")).toBe(1);
    expect(typeNumber("aaaa")).toBe(28);
    expect(typeNumber("DS")).toBe(43);
    expect(typeNumber("DNSKEY")).toBe(48);
    expect(typeNumber("TLSA")).toBe(52);
    expect(typeNumber("CAA")).toBe(257);
  });
  it("throws on unknown", () => {
    expect(() => typeNumber("WHAT")).toThrow();
  });
});

describe("encodeName", () => {
  it("encodes root", () => {
    expect(encodeName(".")).toEqual(Buffer.from([0]));
    expect(encodeName("")).toEqual(Buffer.from([0]));
  });
  it("encodes a single label", () => {
    expect(encodeName("Com")).toEqual(Buffer.from([3, 0x63, 0x6f, 0x6d, 0]));
  });
  it("encodes multi-label, lowercases", () => {
    expect(encodeName("EXAMPLE.com.")).toEqual(
      Buffer.from([7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]),
    );
  });
  it("rejects empty labels", () => {
    expect(() => encodeName("foo..bar")).toThrow();
  });
  it("rejects labels >63 bytes", () => {
    expect(() => encodeName("a".repeat(64) + ".com")).toThrow();
  });
});

describe("encodeIPv4", () => {
  it("encodes valid v4", () => {
    expect(encodeIPv4("192.0.2.1")).toEqual(Buffer.from([192, 0, 2, 1]));
  });
  it("throws on too few octets", () => {
    expect(() => encodeIPv4("1.2.3")).toThrow();
  });
  it("throws on out-of-range octet", () => {
    expect(() => encodeIPv4("1.2.3.256")).toThrow();
    expect(() => encodeIPv4("1.2.3.x")).toThrow();
  });
});

describe("encodeIPv6", () => {
  it("encodes fully expanded", () => {
    expect(encodeIPv6("2001:0db8:0000:0000:0000:0000:0000:0001")).toEqual(
      Buffer.concat([Buffer.from([0x20, 0x01, 0x0d, 0xb8]), Buffer.alloc(11), Buffer.from([0x01])]),
    );
  });
  it("encodes :: shorthand at the end", () => {
    expect(encodeIPv6("2001:db8::").subarray(0, 4)).toEqual(Buffer.from([0x20, 0x01, 0x0d, 0xb8]));
    expect(encodeIPv6("2001:db8::").subarray(4)).toEqual(Buffer.alloc(12));
  });
  it("encodes :: shorthand at the start", () => {
    expect(encodeIPv6("::1").subarray(0, 14)).toEqual(Buffer.alloc(14));
    expect(encodeIPv6("::1").subarray(14)).toEqual(Buffer.from([0, 1]));
  });
  it("encodes :: shorthand in middle", () => {
    expect(encodeIPv6("fe80::1").subarray(0, 2)).toEqual(Buffer.from([0xfe, 0x80]));
  });
  it("rejects malformed", () => {
    expect(() => encodeIPv6("not:an:address")).toThrow();
    expect(() => encodeIPv6("1:2:3:4:5:6:7")).toThrow();
    expect(() => encodeIPv6("1:2:3:4:5:6:7:8:9::")).toThrow();
    expect(() => encodeIPv6("1:2:3:4:5:6:7:zzzz")).toThrow();
  });
});

describe("encodeDnskeyRdata", () => {
  it("includes flags, protocol=3, alg, key", () => {
    const out = encodeDnskeyRdata({ flags: 257, algorithm: 8, key: Buffer.from([0xaa]) });
    expect(out[0]).toBe(1);
    expect(out[1]).toBe(0x01);
    expect(out[2]).toBe(3);
    expect(out[3]).toBe(8);
    expect(out[4]).toBe(0xaa);
  });
});

describe("encodeDsRdata", () => {
  it("encodes DS RDATA fields", () => {
    const out = encodeDsRdata({
      keyTag: 0xabcd,
      algorithm: 8,
      digestType: 2,
      digest: Buffer.from([0x11, 0x22]),
    });
    expect(out).toEqual(Buffer.from([0xab, 0xcd, 8, 2, 0x11, 0x22]));
  });
});

describe("encodeTlsaRdata", () => {
  it("encodes usage/selector/matching/cert", () => {
    expect(
      encodeTlsaRdata({
        usage: 3,
        selector: 1,
        matchingType: 1,
        certificate: Buffer.from([0x99]),
      }),
    ).toEqual(Buffer.from([3, 1, 1, 0x99]));
  });
});

describe("encodeCaaRdata", () => {
  it("encodes with explicit flags", () => {
    expect(encodeCaaRdata({ tag: "issue", value: "letsencrypt.org", flags: 0 })).toEqual(
      Buffer.concat([
        Buffer.from([0, 5]),
        Buffer.from("issue", "ascii"),
        Buffer.from("letsencrypt.org"),
      ]),
    );
  });
  it("encodes with issuerCritical", () => {
    const out = encodeCaaRdata({ tag: "issue", value: "x", issuerCritical: true });
    expect(out[0]).toBe(128);
  });
  it("defaults flags to 0 when no critical/flags", () => {
    const out = encodeCaaRdata({ tag: "issue", value: "x" });
    expect(out[0]).toBe(0);
  });
});

describe("encodeSoaRdata", () => {
  it("encodes all SOA fields", () => {
    const out = encodeSoaRdata({
      mname: "ns.example.",
      rname: "hostmaster.example.",
      serial: 1,
      refresh: 2,
      retry: 3,
      expire: 4,
      minimum: 5,
    });
    expect(out.length).toBeGreaterThan(20);
  });
  it("treats missing numeric fields as 0", () => {
    const out = encodeSoaRdata({ mname: ".", rname: "." });
    expect(out.subarray(-20)).toEqual(Buffer.alloc(20));
  });
});

describe("encodeRdata", () => {
  it("handles A", () => {
    expect(encodeRdata({ name: "x", type: "A", data: "1.2.3.4" })).toEqual(
      Buffer.from([1, 2, 3, 4]),
    );
  });
  it("handles AAAA", () => {
    expect(encodeRdata({ name: "x", type: "AAAA", data: "::1" }).length).toBe(16);
  });
  it("handles NS/CNAME/PTR via name", () => {
    expect(encodeRdata({ name: "x", type: "NS", data: "ns.example." }).length).toBeGreaterThan(0);
    expect(encodeRdata({ name: "x", type: "CNAME", data: "y.example." }).length).toBeGreaterThan(0);
    expect(encodeRdata({ name: "x", type: "PTR", data: "y.example." }).length).toBeGreaterThan(0);
  });
  it("handles DNSKEY", () => {
    expect(
      encodeRdata({
        name: "x",
        type: "DNSKEY",
        data: { flags: 256, algorithm: 13, key: Buffer.alloc(0) },
      }).length,
    ).toBe(4);
  });
  it("handles DS", () => {
    expect(
      encodeRdata({
        name: "x",
        type: "DS",
        data: { keyTag: 1, algorithm: 1, digestType: 2, digest: Buffer.alloc(0) },
      }).length,
    ).toBe(4);
  });
  it("handles TLSA, CAA, SOA", () => {
    expect(
      encodeRdata({
        name: "x",
        type: "TLSA",
        data: { usage: 0, selector: 0, matchingType: 0, certificate: Buffer.alloc(0) },
      }).length,
    ).toBe(3);
    expect(
      encodeRdata({ name: "x", type: "CAA", data: { tag: "issue", value: "x", flags: 0 } }).length,
    ).toBeGreaterThan(0);
    expect(
      encodeRdata({
        name: "x",
        type: "SOA",
        data: { mname: ".", rname: ".", serial: 0, refresh: 0, retry: 0, expire: 0, minimum: 0 },
      }).length,
    ).toBeGreaterThan(0);
  });
  it("throws on unsupported type", () => {
    expect(() =>
      encodeRdata({ name: "x", type: "MX", data: { preference: 10, exchange: "y" } }),
    ).toThrow();
  });
});

describe("encodeRrForSigning", () => {
  it("encodes a sorted RRset", () => {
    const rrset = [
      { name: "ex.", type: "A" as const, data: "1.2.3.4" },
      { name: "ex.", type: "A" as const, data: "1.1.1.1" },
    ];
    const out = encodeRrForSigning(rrset, {
      typeCovered: "A",
      algorithm: 8,
      labels: 1,
      originalTTL: 60,
      expiration: 0,
      inception: 0,
      keyTag: 0,
      signersName: ".",
      signature: Buffer.alloc(0),
    });
    expect(out.length).toBeGreaterThan(0);
  });
  it("throws on empty RRset", () => {
    expect(() =>
      encodeRrForSigning([], {
        typeCovered: "A",
        algorithm: 8,
        labels: 1,
        originalTTL: 60,
        expiration: 0,
        inception: 0,
        keyTag: 0,
        signersName: ".",
        signature: Buffer.alloc(0),
      }),
    ).toThrow();
  });
});

describe("rrsigSigningInput", () => {
  it("concatenates RRSIG header and RR data", () => {
    const out = rrsigSigningInput(
      {
        typeCovered: "A",
        algorithm: 8,
        labels: 1,
        originalTTL: 60,
        expiration: 0,
        inception: 0,
        keyTag: 0,
        signersName: ".",
        signature: Buffer.alloc(0),
      },
      [{ name: "ex.", type: "A", data: "1.2.3.4" }],
    );
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("encodeRrsigRdataForSigning", () => {
  it("includes all header fields", () => {
    const out = encodeRrsigRdataForSigning({
      typeCovered: "A",
      algorithm: 8,
      labels: 2,
      originalTTL: 3600,
      expiration: 0x01020304,
      inception: 0x05060708,
      keyTag: 0xabcd,
      signersName: "example.",
      signature: Buffer.alloc(0),
    });
    expect(out.subarray(0, 2)).toEqual(Buffer.from([0, 1])); // typeCovered=A=1
    expect(out[2]).toBe(8);
    expect(out[3]).toBe(2);
  });
});

describe("computeKeyTag and computeDsDigest", () => {
  it("computes a key tag and SHA-256 digest", () => {
    const dnskey = { flags: 257, algorithm: 8, key: Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]) };
    const tag = computeKeyTag(dnskey);
    expect(tag).toBeGreaterThanOrEqual(0);
    expect(tag).toBeLessThanOrEqual(0xffff);
    expect(computeDsDigest("example.", dnskey, 2).length).toBe(32);
    expect(computeDsDigest("example.", dnskey, 1).length).toBe(20);
    expect(computeDsDigest("example.", dnskey, 4).length).toBe(48);
  });
  it("throws on unsupported digest type", () => {
    expect(() =>
      computeDsDigest("x.", { flags: 0, algorithm: 0, key: Buffer.alloc(0) }, 99),
    ).toThrow();
  });
});
