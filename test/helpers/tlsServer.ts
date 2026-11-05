import { once } from "node:events";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import tls from "node:tls";

const fixtures = join(import.meta.dirname, "..", "fixtures");

/** Self-signed localhost certificate (test fixture, valid until 2126). */
export const TEST_CERT = readFileSync(join(fixtures, "localhost-cert.pem"));
export const TEST_KEY = readFileSync(join(fixtures, "localhost-key.pem"));

export interface LocalTlsServer extends AsyncDisposable {
  port: number;
}

/**
 * Starts a TLS server on 127.0.0.1 with the test certificate. `onConnection` gets each
 * secure socket; omit it to just complete the handshake and leave the socket open.
 */
export async function startTlsServer(
  onConnection: (socket: tls.TLSSocket) => void = () => {},
): Promise<LocalTlsServer> {
  const sockets = new Set<tls.TLSSocket>();
  const server = tls.createServer({ cert: TEST_CERT, key: TEST_KEY }, (socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket));
    onConnection(socket);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no TCP address");
  return {
    port: address.port,
    async [Symbol.asyncDispose]() {
      for (const s of sockets) s.destroy();
      server.close();
      await once(server, "close");
    },
  };
}

/** Starts a TLS server that answers every request with the given raw HTTP response. */
export function startHttpsServer(rawResponse: string | Buffer): Promise<LocalTlsServer> {
  return startTlsServer((socket) => {
    socket.once("data", () => socket.end(rawResponse));
  });
}
