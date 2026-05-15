import { Buffer } from "node:buffer";
import dgram from "node:dgram";
import net from "node:net";
import dnsPacket from "dns-packet";
import { describe, expect, it } from "vitest";
import { createDnsTransport, queryTcp, queryUdp } from "../../src/net/dns.ts";

interface UdpServer {
  port: number;
  close: () => Promise<void>;
}

async function startUdpServer(
  handler: (msg: Buffer) => Buffer | null,
  port = 0,
): Promise<UdpServer> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    socket.on("message", (msg, rinfo) => {
      const resp = handler(msg);
      if (resp) socket.send(resp, rinfo.port, rinfo.address);
    });
    socket.bind(port, "127.0.0.1", () => {
      const addr = socket.address();
      resolve({
        port: addr.port,
        close: () =>
          new Promise<void>((res) => {
            socket.close(() => res());
          }),
      });
    });
  });
}

interface TcpServer {
  port: number;
  close: () => Promise<void>;
}

async function startTcpServer(
  handler: (msg: Buffer) => Buffer | null,
  port = 0,
): Promise<TcpServer> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        const buf = Buffer.concat(chunks);
        if (buf.length >= 2) {
          const len = buf.readUInt16BE(0);
          if (buf.length >= 2 + len) {
            const query = buf.subarray(2, 2 + len);
            const resp = handler(query);
            if (resp) {
              const lenBuf = Buffer.alloc(2);
              lenBuf.writeUInt16BE(resp.length, 0);
              socket.end(Buffer.concat([lenBuf, resp]));
            } else {
              socket.end();
            }
          }
        }
      });
    });
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      if (typeof addr === "object" && addr) {
        resolve({
          port: addr.port,
          close: () =>
            new Promise<void>((res) => {
              server.close(() => res());
            }),
        });
      }
    });
  });
}

async function startTcpEarlyCloseServer(): Promise<TcpServer> {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      socket.once("data", () => socket.end());
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (typeof addr === "object" && addr) {
        resolve({
          port: addr.port,
          close: () =>
            new Promise<void>((res) => {
              server.close(() => res());
            }),
        });
      }
    });
  });
}

function buildResponse(query: Buffer, answer: dnsPacket.Answer | null, truncated: boolean): Buffer {
  const decoded = dnsPacket.decode(query);
  let flags = (truncated ? dnsPacket.TRUNCATED_RESPONSE : 0) | dnsPacket.RECURSION_DESIRED;
  flags |= 1 << 15; // QR = 1
  return dnsPacket.encode({
    type: "response",
    id: decoded.id ?? 0,
    flags,
    questions: decoded.questions ?? [],
    answers: answer ? [answer] : [],
  });
}

describe("queryUdp", () => {
  it("returns the response message", async () => {
    const server = await startUdpServer((msg) =>
      buildResponse(msg, { name: "x.test", type: "A", data: "1.2.3.4" }, false),
    );
    try {
      const query = dnsPacket.encode({
        type: "query",
        id: 1,
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [{ name: "x.test", type: "A" }],
      });
      const r = await queryUdp(query, "127.0.0.1", server.port, 1000);
      expect(r.length).toBeGreaterThan(0);
    } finally {
      await server.close();
    }
  });

  it("rejects when the address is invalid", async () => {
    const query = Buffer.alloc(12);
    await expect(queryUdp(query, "not-an-ip", 53, 500)).rejects.toThrow();
  });

  it("times out when no response arrives", async () => {
    const server = await startUdpServer(() => null);
    try {
      const query = dnsPacket.encode({
        type: "query",
        id: 1,
        questions: [{ name: "x.test", type: "A" }],
      });
      await expect(queryUdp(query, "127.0.0.1", server.port, 100)).rejects.toThrow(/timed out/);
    } finally {
      await server.close();
    }
  });
});

describe("queryTcp", () => {
  it("returns the response message", async () => {
    const server = await startTcpServer((msg) =>
      buildResponse(msg, { name: "x.test", type: "A", data: "1.2.3.4" }, false),
    );
    try {
      const query = dnsPacket.encode({
        type: "query",
        id: 2,
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [{ name: "x.test", type: "A" }],
      });
      const r = await queryTcp(query, "127.0.0.1", server.port, 1000);
      expect(r.length).toBeGreaterThan(0);
    } finally {
      await server.close();
    }
  });

  it("rejects when port is closed", async () => {
    const query = Buffer.alloc(12);
    await expect(queryTcp(query, "127.0.0.1", 1, 500)).rejects.toThrow();
  });

  it("rejects when the server closes before sending a response", async () => {
    const server = await startTcpEarlyCloseServer();
    try {
      const query = Buffer.alloc(12);
      await expect(queryTcp(query, "127.0.0.1", server.port, 1000)).rejects.toThrow(
        /closed before response was complete/,
      );
    } finally {
      await server.close();
    }
  });
});

describe("createDnsTransport", () => {
  it("returns decoded packet over UDP", async () => {
    const server = await startUdpServer((msg) =>
      buildResponse(msg, { name: "x.test", type: "A", data: "1.2.3.4" }, false),
    );
    try {
      const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
      const r = await t.query({ type: "A", name: "x.test", port: server.port });
      expect(r.answers?.[0]?.type).toBe("A");
    } finally {
      await server.close();
    }
  });

  it("supports DNSSEC DO bit and recursive=false", async () => {
    const server = await startUdpServer((msg) =>
      buildResponse(msg, { name: "x.test", type: "A", data: "1.2.3.4" }, false),
    );
    try {
      const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
      const r = await t.query({
        type: "A",
        name: "x.test",
        port: server.port,
        dnssec: true,
        recursive: false,
      });
      expect(r.answers?.[0]?.type).toBe("A");
    } finally {
      await server.close();
    }
  });

  it("propagates non-timeout UDP errors", async () => {
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 100 });
    await expect(t.query({ type: "A", name: "x.test", server: "not-an-ip" })).rejects.toThrow();
  });

  it("falls back to TCP when the UDP response sets the TC (truncated) flag", async () => {
    const udp = await startUdpServer((msg) =>
      buildResponse(msg, { name: "x.test", type: "A", data: "1.2.3.4" }, true),
    );
    const tcp = await startTcpServer(
      (msg) => buildResponse(msg, { name: "x.test", type: "A", data: "9.9.9.9" }, false),
      udp.port,
    );
    try {
      const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
      const r = await t.query({ type: "A", name: "x.test", port: udp.port });
      expect(r.answers?.[0]?.type).toBe("A");
      expect((r.answers?.[0] as { data?: string } | undefined)?.data).toBe("9.9.9.9");
    } finally {
      await tcp.close();
      await udp.close();
    }
  });
});
