import { Buffer } from "node:buffer";
import { randomInt } from "node:crypto";
import dgram from "node:dgram";
import { once } from "node:events";
import net from "node:net";
import { isIPv4, isIPv6 } from "node:net";
import dnsPacket from "dns-packet";
/** A DNS query got no (matching) answer within its time limit. */
export class DnsTimeoutError extends Error {
    name = "DnsTimeoutError";
}
function buildQuery(opts) {
    const flags = opts.recursive === false ? 0 : dnsPacket.RECURSION_DESIRED;
    const packet = {
        type: "query",
        // Unpredictable 16-bit ID: replies are only accepted when they echo it.
        id: randomInt(0x10000),
        flags,
        questions: [{ type: opts.type, name: opts.name, class: "IN" }],
    };
    if (opts.dnssec) {
        packet.additionals = [
            {
                type: "OPT",
                name: ".",
                udpPayloadSize: 4096,
                extendedRcode: 0,
                ednsVersion: 0,
                flags: dnsPacket.DNSSEC_OK,
                flag_do: true,
                options: [],
            },
        ];
    }
    return dnsPacket.encode(packet);
}
function udpFamily(addr) {
    if (isIPv6(addr))
        return "udp6";
    if (isIPv4(addr))
        return "udp4";
    throw new Error(`not an IP address: ${addr}`);
}
function sameId(a, b) {
    return a.length >= 2 && b.length >= 2 && a.readUInt16BE(0) === b.readUInt16BE(0);
}
/**
 * Sends `query` over UDP and resolves with the first reply that carries the same ID.
 * Rejects with `DnsTimeoutError` if none arrives within `timeoutMs`.
 */
export async function queryUdp(query, server, port, timeoutMs) {
    const signal = AbortSignal.timeout(timeoutMs);
    await using socket = dgram.createSocket(udpFamily(server));
    // Re-emit send failures (e.g. EMSGSIZE) as "error", which the once() below rejects on.
    socket.send(query, port, server, (err) => {
        if (err)
            socket.emit("error", err);
    });
    try {
        while (true) {
            const [msg] = (await once(socket, "message", { signal }));
            if (sameId(msg, query))
                return msg;
        }
    }
    catch (err) {
        if (signal.aborted)
            throw new DnsTimeoutError(`DNS UDP query timed out after ${timeoutMs}ms`);
        throw err;
    }
}
/**
 * Sends `query` over TCP (2-byte length prefix, RFC 1035 §4.2.2) and resolves with the
 * reply. Rejects with `DnsTimeoutError` if it doesn't complete within `timeoutMs`.
 */
export async function queryTcp(query, server, port, timeoutMs) {
    const signal = AbortSignal.timeout(timeoutMs);
    // On abort, net.connect destroys the socket, which ends the awaits below.
    const socket = net.connect({ host: server, port, signal });
    try {
        await once(socket, "connect");
        const len = Buffer.alloc(2);
        len.writeUInt16BE(query.length, 0);
        socket.write(Buffer.concat([len, query]));
        const chunks = [];
        let received = 0;
        let expected = -1;
        for await (const chunk of socket) {
            chunks.push(chunk);
            received += chunk.length;
            if (expected === -1 && received >= 2)
                expected = Buffer.concat(chunks, 2).readUInt16BE(0);
            if (expected !== -1 && received >= expected + 2) {
                return Buffer.concat(chunks, received).subarray(2, 2 + expected);
            }
        }
        throw new Error("DNS TCP connection closed before response was complete");
    }
    catch (err) {
        if (signal.aborted)
            throw new DnsTimeoutError(`DNS TCP query timed out after ${timeoutMs}ms`);
        throw err;
    }
    finally {
        socket.destroy();
    }
}
export function createDnsTransport(defaults) {
    return {
        async query(opts) {
            const server = opts.server ?? defaults.resolver;
            const port = opts.port ?? 53;
            const timeoutMs = opts.timeoutMs ?? defaults.timeoutMs;
            const buf = buildQuery(opts);
            let response;
            try {
                response = await queryUdp(buf, server, port, timeoutMs);
            }
            catch (err) {
                // UDP can be filtered while TCP still works, so retry once over TCP.
                if (!(err instanceof DnsTimeoutError))
                    throw err;
                response = await queryTcp(buf, server, port, timeoutMs);
            }
            let decoded = dnsPacket.decode(response);
            if (decoded.flag_tc) {
                decoded = dnsPacket.decode(await queryTcp(buf, server, port, timeoutMs));
            }
            return decoded;
        },
    };
}
