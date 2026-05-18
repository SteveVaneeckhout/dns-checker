import dgram from "node:dgram";
import net from "node:net";
import { isIPv4, isIPv6 } from "node:net";
import dnsPacket from "dns-packet";
function buildQuery(opts) {
    const id = Math.floor(Math.random() * 0xffff);
    const flags = opts.recursive === false ? 0 : dnsPacket.RECURSION_DESIRED;
    const packet = {
        type: "query",
        id,
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
export function queryUdp(query, server, port, timeoutMs) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const socket = dgram.createSocket(udpFamily(server));
        const timer = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            socket.close();
            reject(new Error(`DNS UDP query timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        socket.once("error", (err) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            socket.close();
            reject(err);
        });
        socket.once("message", (msg) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            socket.close();
            resolve(msg);
        });
        socket.send(query, port, server, (err) => {
            if (err && !settled) {
                settled = true;
                clearTimeout(timer);
                socket.close();
                reject(err);
            }
        });
    });
}
export function queryTcp(query, server, port, timeoutMs) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const chunks = [];
        let expected = -1;
        let received = 0;
        const sock = net.connect({ host: server, port });
        const timer = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            sock.destroy();
            reject(new Error(`DNS TCP query timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        sock.once("connect", () => {
            const len = Buffer.alloc(2);
            len.writeUInt16BE(query.length, 0);
            sock.write(Buffer.concat([len, query]));
        });
        sock.on("data", (chunk) => {
            chunks.push(chunk);
            received += chunk.length;
            const buf = Buffer.concat(chunks);
            if (expected === -1 && buf.length >= 2) {
                expected = buf.readUInt16BE(0);
            }
            if (expected !== -1 && received >= expected + 2) {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timer);
                sock.end();
                resolve(buf.subarray(2, 2 + expected));
            }
        });
        sock.once("error", (err) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            sock.destroy();
            reject(err);
        });
        sock.once("close", () => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            reject(new Error("DNS TCP connection closed before response was complete"));
        });
    });
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
                if (err instanceof Error && /timed out/i.test(err.message)) {
                    response = await queryTcp(buf, server, port, timeoutMs);
                }
                else {
                    throw err;
                }
            }
            let decoded = dnsPacket.decode(response);
            if (decoded.flag_tc) {
                const tcpResponse = await queryTcp(buf, server, port, timeoutMs);
                decoded = dnsPacket.decode(tcpResponse);
            }
            return decoded;
        },
    };
}
