import type { DetailedPeerCertificate, PeerCertificate } from "node:tls";
import { describe, expect, it } from "vitest";
import {
  certIssuerString,
  certSubjectAltNames,
  certSubjectCN,
  collectChain,
  createTlsTransport,
} from "../../src/net/tls.ts";

function makeCert(over: Partial<PeerCertificate> = {}): PeerCertificate {
  return {
    subject: { CN: "host.test", C: "", ST: "", L: "", O: "", OU: "" },
    issuer: { CN: "Let's Encrypt R3", O: "Let's Encrypt", C: "", ST: "", L: "", OU: "" },
    raw: Buffer.alloc(0),
    valid_from: "",
    valid_to: "",
    fingerprint: "",
    fingerprint256: "",
    fingerprint512: "",
    serialNumber: "",
    ...over,
  } as unknown as PeerCertificate;
}

describe("certIssuerString", () => {
  it("formats O and CN", () => {
    expect(certIssuerString(makeCert())).toBe("O=Let's Encrypt, CN=Let's Encrypt R3");
  });
  it("returns empty for empty issuer", () => {
    expect(
      certIssuerString(
        makeCert({
          issuer: { CN: "", O: "", C: "", ST: "", L: "", OU: "" },
        } as Partial<PeerCertificate>),
      ),
    ).toBe("");
  });
  it("handles missing issuer property", () => {
    expect(certIssuerString({ issuer: undefined } as unknown as PeerCertificate)).toBe("");
  });
  it("handles array CN/O values", () => {
    const c = makeCert({
      issuer: {
        CN: ["A", "B"],
        O: ["Org"],
        C: "",
        ST: "",
        L: "",
        OU: "",
      } as PeerCertificate["issuer"],
    });
    expect(certIssuerString(c)).toBe("O=Org, CN=A");
  });
});

describe("certSubjectCN", () => {
  it("returns CN", () => {
    expect(certSubjectCN(makeCert())).toBe("host.test");
  });
  it("returns empty for missing CN", () => {
    expect(certSubjectCN(makeCert({ subject: { CN: "" } as PeerCertificate["subject"] }))).toBe("");
  });
});

describe("certSubjectAltNames", () => {
  it("parses DNS entries", () => {
    expect(
      certSubjectAltNames(makeCert({ subjectaltname: "DNS:foo.test, DNS:bar.test, IP:1.2.3.4" })),
    ).toEqual(["foo.test", "bar.test"]);
  });
  it("returns empty when missing", () => {
    expect(certSubjectAltNames(makeCert())).toEqual([]);
  });
});

describe("collectChain", () => {
  function makeNode(label: string): DetailedPeerCertificate {
    return { subject: { CN: label } } as unknown as DetailedPeerCertificate;
  }
  function link(child: DetailedPeerCertificate, parent: DetailedPeerCertificate): void {
    (child as { issuerCertificate?: DetailedPeerCertificate }).issuerCertificate = parent;
  }

  it("returns a single-entry chain for a self-signed root", () => {
    const root = makeNode("root");
    link(root, root);
    const chain = collectChain(root);
    expect(chain).toHaveLength(1);
    expect(chain[0]).toBe(root);
  });

  it("walks a linear leaf → intermediate → root chain", () => {
    const root = makeNode("root");
    const intermediate = makeNode("intermediate");
    const leaf = makeNode("leaf");
    link(root, root);
    link(intermediate, root);
    link(leaf, intermediate);
    const chain = collectChain(leaf);
    expect(chain.map((c) => (c.subject as { CN: string }).CN)).toEqual([
      "leaf",
      "intermediate",
      "root",
    ]);
  });

  it("stops on a cycle without looping forever", () => {
    const a = makeNode("a");
    const b = makeNode("b");
    const leaf = makeNode("leaf");
    link(leaf, a);
    link(a, b);
    link(b, leaf);
    const chain = collectChain(leaf);
    expect(chain).toHaveLength(3);
    expect(chain.map((c) => (c.subject as { CN: string }).CN)).toEqual(["leaf", "a", "b"]);
  });
});

describe("createTlsTransport (error paths)", () => {
  it("rejects when remote port is closed", async () => {
    const t = createTlsTransport();
    await expect(
      t.handshake({
        address: "127.0.0.1",
        port: 1,
        servername: "localhost",
        timeoutMs: 500,
      }),
    ).rejects.toThrow();
  });
});
