import { Buffer } from "node:buffer";
import dgram from "node:dgram";
import { once } from "node:events";
import net, { type AddressInfo } from "node:net";
import dnsPacket from "dns-packet";
import { describe, expect, it } from "vitest";
import { createDnsTransport, DnsTimeoutError, queryTcp, queryUdp } from "../../src/net/dns.ts";

interface LocalServer extends AsyncDisposable {
  port: number;
}

/** UDP DNS server on 127.0.0.1; `handler` returns the reply, or null to stay silent. */
async function startUdpServer(
  handler: (msg: Buffer) => Buffer | null,
  port = 0,
): Promise<LocalServer> {
  const socket = dgram.createSocket("udp4");
  socket.on("message", (msg, rinfo) => {
    const resp = handler(msg);
    if (resp) socket.send(resp, rinfo.port, rinfo.address);
  });
  socket.bind(port, "127.0.0.1");
  await once(socket, "listening");
  return {
    port: socket.address().port,
    [Symbol.asyncDispose]: () => socket[Symbol.asyncDispose](),
  };
}

/** TCP server on 127.0.0.1 that hands every connection to `onConnection`. */
async function startTcpListener(
  onConnection: (socket: net.Socket) => void,
  port = 0,
): Promise<LocalServer> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    onConnection(socket);
  });
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return {
    port: (server.address() as AddressInfo).port,
    async [Symbol.asyncDispose]() {
      for (const s of sockets) s.destroy();
      await server[Symbol.asyncDispose]();
    },
  };
}

/** TCP DNS server (2-byte length framing); `handler` returns the reply, or null to hang up. */
function startTcpServer(handler: (msg: Buffer) => Buffer | null, port = 0): Promise<LocalServer> {
  return startTcpListener((socket) => {
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length < 2) return;
      const len = buf.readUInt16BE(0);
      if (buf.length < 2 + len) return;
      const resp = handler(buf.subarray(2, 2 + len));
      if (resp) {
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(resp.length, 0);
        socket.end(Buffer.concat([lenBuf, resp]));
      } else {
        socket.end();
      }
    });
  }, port);
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

const A_ANSWER: dnsPacket.Answer = { name: "x.test", type: "A", data: "1.2.3.4" };

function encodeQuery(id: number): Buffer {
  return dnsPacket.encode({
    type: "query",
    id,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ name: "x.test", type: "A" }],
  });
}

describe("queryUdp", () => {
  it("returns the response message", async () => {
    await using server = await startUdpServer((msg) => buildResponse(msg, A_ANSWER, false));
    const r = await queryUdp(encodeQuery(1), "127.0.0.1", server.port, 1000);
    expect(dnsPacket.decode(r).id).toBe(1);
  });

  it("ignores replies whose ID does not match the query", async () => {
    await using server = await startUdpServer((msg) => {
      const wrongId = Buffer.from(buildResponse(msg, A_ANSWER, false));
      wrongId.writeUInt16BE((msg.readUInt16BE(0) + 1) & 0xffff, 0);
      return wrongId;
    });
    await expect(queryUdp(encodeQuery(7), "127.0.0.1", server.port, 150)).rejects.toThrow(
      DnsTimeoutError,
    );
  });

  it("ignores runt datagrams too short to carry an ID", async () => {
    await using server = await startUdpServer(() => Buffer.from([0x00]));
    await expect(queryUdp(encodeQuery(7), "127.0.0.1", server.port, 150)).rejects.toThrow(
      DnsTimeoutError,
    );
  });

  it("rejects when the address is invalid", async () => {
    const query = Buffer.alloc(12);
    await expect(queryUdp(query, "not-an-ip", 53, 500)).rejects.toThrow(/not an IP address/);
  });

  it("times out with DnsTimeoutError when no response arrives", async () => {
    await using server = await startUdpServer(() => null);
    const err = await queryUdp(encodeQuery(1), "127.0.0.1", server.port, 100).catch((e) => e);
    expect(err).toBeInstanceOf(DnsTimeoutError);
    expect((err as Error).message).toMatch(/timed out after 100ms/);
  });

  it("rejects with the socket error when sending fails", async () => {
    const tooBig = Buffer.alloc(70_000);
    await expect(queryUdp(tooBig, "127.0.0.1", 9, 500)).rejects.toThrow(/EMSGSIZE/);
  });
});

describe("queryTcp", () => {
  it("returns the response message", async () => {
    await using server = await startTcpServer((msg) => buildResponse(msg, A_ANSWER, false));
    const r = await queryTcp(encodeQuery(2), "127.0.0.1", server.port, 1000);
    expect(dnsPacket.decode(r).id).toBe(2);
  });

  it("reassembles a response split into single bytes", async () => {
    await using server = await startTcpListener((socket) => {
      socket.once("data", async (data: Buffer) => {
        const resp = buildResponse(data.subarray(2), A_ANSWER, false);
        const framed = Buffer.concat([Buffer.from([resp.length >> 8, resp.length & 0xff]), resp]);
        socket.setNoDelay(true);
        for (const byte of framed) {
          socket.write(Buffer.from([byte]));
          await new Promise((r) => setImmediate(r));
        }
        socket.end();
      });
    });
    const r = await queryTcp(encodeQuery(3), "127.0.0.1", server.port, 2000);
    expect(dnsPacket.decode(r).answers?.[0]?.type).toBe("A");
  });

  it("rejects when port is closed", async () => {
    const query = Buffer.alloc(12);
    await expect(queryTcp(query, "127.0.0.1", 1, 500)).rejects.toThrow();
  });

  it("rejects when the server closes before sending a response", async () => {
    await using server = await startTcpListener((socket) => {
      socket.once("data", () => socket.end());
    });
    await expect(queryTcp(Buffer.alloc(12), "127.0.0.1", server.port, 1000)).rejects.toThrow(
      /closed before response was complete/,
    );
  });

  it("times out with DnsTimeoutError when the server never answers", async () => {
    await using server = await startTcpListener(() => {});
    const err = await queryTcp(encodeQuery(4), "127.0.0.1", server.port, 100).catch((e) => e);
    expect(err).toBeInstanceOf(DnsTimeoutError);
    expect((err as Error).message).toMatch(/DNS TCP query timed out after 100ms/);
  });
});

describe("createDnsTransport", () => {
  it("returns decoded packet over UDP", async () => {
    await using server = await startUdpServer((msg) => buildResponse(msg, A_ANSWER, false));
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
    const r = await t.query({ type: "A", name: "x.test", port: server.port });
    expect(r.answers?.[0]?.type).toBe("A");
  });

  it("supports DNSSEC DO bit and recursive=false", async () => {
    let query: dnsPacket.DecodedPacket | undefined;
    await using server = await startUdpServer((msg) => {
      query = dnsPacket.decode(msg);
      return buildResponse(msg, A_ANSWER, false);
    });
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
    const r = await t.query({
      type: "A",
      name: "x.test",
      port: server.port,
      dnssec: true,
      recursive: false,
    });
    expect(r.answers?.[0]?.type).toBe("A");
    expect(query?.flag_rd).toBe(false);
    expect(query?.additionals?.[0]?.type).toBe("OPT");
  });

  it("propagates non-timeout UDP errors", async () => {
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 100 });
    await expect(t.query({ type: "A", name: "x.test", server: "not-an-ip" })).rejects.toThrow();
  });

  it("falls back to TCP when the UDP response sets the TC (truncated) flag", async () => {
    await using udp = await startUdpServer((msg) => buildResponse(msg, A_ANSWER, true));
    await using _tcp = await startTcpServer(
      (msg) => buildResponse(msg, { name: "x.test", type: "A", data: "9.9.9.9" }, false),
      udp.port,
    );
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
    const r = await t.query({ type: "A", name: "x.test", port: udp.port });
    expect(r.answers?.[0]?.type).toBe("A");
    expect((r.answers?.[0] as { data?: string } | undefined)?.data).toBe("9.9.9.9");
  });

  it("retries over TCP when the UDP query times out", async () => {
    await using udp = await startUdpServer(() => null);
    await using _tcp = await startTcpServer(
      (msg) => buildResponse(msg, { name: "x.test", type: "A", data: "8.8.4.4" }, false),
      udp.port,
    );
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 200 });
    const r = await t.query({ type: "A", name: "x.test", port: udp.port });
    expect((r.answers?.[0] as { data?: string } | undefined)?.data).toBe("8.8.4.4");
  });

  it("uses a random query ID", async () => {
    const ids = new Set<number>();
    await using server = await startUdpServer((msg) => {
      ids.add(msg.readUInt16BE(0));
      return buildResponse(msg, A_ANSWER, false);
    });
    const t = createDnsTransport({ resolver: "127.0.0.1", timeoutMs: 1000 });
    for (let i = 0; i < 5; i++) await t.query({ type: "A", name: "x.test", port: server.port });
    expect(ids.size).toBeGreaterThan(1);
  });
});
