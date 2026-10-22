import type { LookupAddress } from "node:dns";
import net from "node:net";
import { resolvePublicAddresses } from "./ssrf.js";

/**
 * SSRF egress proxy for the Playwright browser (see browser.ts).
 *
 * Playwright never calls page.route / context.route handlers for redirect
 * hops — Chromium continues them internally — so a URL that passes every
 * check and then answers `302 Location: http://169.254.169.254/...` would be
 * followed unchecked. Route interception also misses popups, service workers
 * and websockets. So instead of relying on interception, the browser is
 * launched with this local SOCKS5 proxy as its only way out: every TCP
 * connection Chromium opens, for any URL and at any redirect hop, arrives here
 * as a SOCKS5 CONNECT. The destination is resolved and range-checked by
 * resolvePublicAddresses() (the same rule as assertUrlSafe), and the upstream
 * socket is opened only to the addresses that passed — there is no second DNS
 * lookup for an attacker to rebind between the check and the connect.
 *
 * For a socks5 proxy Playwright launches Chromium with
 * `--host-resolver-rules=MAP * ~NOTFOUND`, so the browser resolves nothing
 * itself and hands hostnames to the proxy; browser.ts passes the `<-loopback>`
 * bypass rule so localhost and link-local destinations are proxied (and
 * refused here) instead of being connected to directly.
 *
 * Only the no-auth method and the CONNECT command are supported (no BIND, no
 * UDP ASSOCIATE), and the proxy listens on 127.0.0.1 only.
 */

const SOCKS_VERSION = 0x05;
const AUTH_NONE = 0x00;
const AUTH_NO_ACCEPTABLE = 0xff;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;
const REP_SUCCEEDED = 0x00;
const REP_GENERAL_FAILURE = 0x01;
const REP_NOT_ALLOWED = 0x02;
const REP_HOST_UNREACHABLE = 0x04;
const REP_COMMAND_NOT_SUPPORTED = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

// A client that has not finished the SOCKS handshake in this window is dropped.
const HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * Destination policy: returns the addresses `host` may be connected to, or
 * throws to refuse it. Production uses resolvePublicAddresses; tests inject a
 * stub so a hermetic test can stand in for a public host.
 */
export type DestinationResolver = (host: string) => Promise<string[]>;

export interface EgressProxy {
  /** socks5://127.0.0.1:<port> — pass to chromium.launch({ proxy }). */
  readonly url: string;
  close(): Promise<void>;
}

interface ConnectRequest {
  host: string;
  port: number;
  /** Bytes the request occupied in the buffer. */
  size: number;
}

/** SOCKS5 reply with an all-zero bound address. */
function replyBytes(code: number): Buffer {
  return Buffer.from([SOCKS_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
}

function refuse(client: net.Socket, code: number): void {
  client.end(replyBytes(code));
  client.resume(); // drain so the client's FIN is seen and the socket closes
  client.setTimeout(HANDSHAKE_TIMEOUT_MS); // reap it if the client never closes
}

/** Parses a SOCKS5 request: null = need more bytes, number = reply code to refuse with. */
function parseRequest(buf: Buffer): ConnectRequest | number | null {
  if (buf.length < 5) return null;
  if (buf[0] !== SOCKS_VERSION) return REP_GENERAL_FAILURE;
  if (buf[1] !== CMD_CONNECT) return REP_COMMAND_NOT_SUPPORTED;

  let host: string;
  let offset: number;
  switch (buf[3]) {
    case ATYP_IPV4:
      offset = 8;
      if (buf.length < offset + 2) return null;
      host = Array.from(buf.subarray(4, 8)).join(".");
      break;
    case ATYP_DOMAIN:
      offset = 5 + buf[4];
      if (buf.length < offset + 2) return null;
      host = buf.subarray(5, offset).toString("latin1");
      if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
      break;
    case ATYP_IPV6: {
      offset = 20;
      if (buf.length < offset + 2) return null;
      const groups: string[] = [];
      for (let i = 4; i < 20; i += 2) groups.push(buf.readUInt16BE(i).toString(16));
      host = groups.join(":");
      break;
    }
    default:
      return REP_ADDRESS_TYPE_NOT_SUPPORTED;
  }
  return { host, port: buf.readUInt16BE(offset), size: offset + 2 };
}

async function connectUpstream(
  client: net.Socket,
  request: ConnectRequest,
  early: Buffer,
  resolve: DestinationResolver,
): Promise<void> {
  let addresses: string[];
  try {
    addresses = await resolve(request.host);
  } catch {
    refuse(client, REP_NOT_ALLOWED);
    return;
  }
  if (client.destroyed) return;
  if (addresses.length === 0) {
    refuse(client, REP_NOT_ALLOWED);
    return;
  }

  // Connect only to the addresses that were just checked: this lookup hands
  // Node's connect (and its IPv6/IPv4 fallback) the vetted list instead of
  // resolving the name a second time. An IP-literal host skips lookup and is
  // itself the vetted address.
  const vetted: LookupAddress[] = addresses.map((address) => ({ address, family: net.isIP(address) }));
  const pinnedLookup: net.LookupFunction = (_hostname, options, callback) => {
    if (options.all) callback(null, vetted);
    else callback(null, vetted[0].address, vetted[0].family);
  };

  let upstream: net.Socket;
  try {
    upstream = net.connect({
      host: request.host,
      port: request.port,
      lookup: pinnedLookup,
      autoSelectFamily: true,
    });
  } catch {
    refuse(client, REP_GENERAL_FAILURE);
    return;
  }

  let connected = false;
  upstream.on("error", () => {
    if (connected) client.destroy();
    else refuse(client, REP_HOST_UNREACHABLE);
    upstream.destroy();
  });
  upstream.on("close", () => {
    if (connected) client.destroy();
  });
  client.on("close", () => upstream.destroy());

  upstream.once("connect", () => {
    connected = true;
    client.write(replyBytes(REP_SUCCEEDED));
    if (early.length > 0) upstream.write(early);
    client.pipe(upstream);
    upstream.pipe(client);
  });
}

function handleClient(client: net.Socket, resolve: DestinationResolver): void {
  let buffered = Buffer.alloc(0);
  let greeted = false;
  client.on("timeout", () => client.destroy());
  client.on("error", () => client.destroy());
  client.setTimeout(HANDSHAKE_TIMEOUT_MS);

  const onData = (chunk: Buffer): void => {
    buffered = Buffer.concat([buffered, chunk]);

    if (!greeted) {
      if (buffered.length < 2) return;
      const methodsEnd = 2 + buffered[1];
      if (buffered.length < methodsEnd) return;
      if (buffered[0] !== SOCKS_VERSION) {
        client.off("data", onData);
        client.destroy();
        return;
      }
      if (!buffered.subarray(2, methodsEnd).includes(AUTH_NONE)) {
        client.off("data", onData);
        client.end(Buffer.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]));
        return;
      }
      client.write(Buffer.from([SOCKS_VERSION, AUTH_NONE]));
      buffered = buffered.subarray(methodsEnd);
      greeted = true;
    }

    const request = parseRequest(buffered);
    if (request === null) return;
    client.off("data", onData);
    client.pause();
    // Handshake done: from here the connection lives as long as the browser
    // keeps it (a slow upstream connect or a long-lived socket is not cut).
    client.setTimeout(0);
    if (typeof request === "number") {
      refuse(client, request);
      return;
    }
    connectUpstream(client, request, buffered.subarray(request.size), resolve).catch(() => client.destroy());
  };
  client.on("data", onData);
}

/** Starts the egress proxy on an ephemeral 127.0.0.1 port. */
export async function startEgressProxy(
  resolve: DestinationResolver = resolvePublicAddresses,
): Promise<EgressProxy> {
  const clients = new Set<net.Socket>();
  const server = net.createServer((client) => {
    clients.add(client);
    client.once("close", () => clients.delete(client));
    handleClient(client, resolve);
  });

  await new Promise<void>((listening, failed) => {
    server.once("error", failed);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", failed);
      listening();
    });
  });
  // An accept error (e.g. EMFILE) must not crash the server process; the
  // affected connection simply fails, which Chromium reports as a proxy error.
  server.on("error", () => {});
  // The listener alone must not keep the process alive (the HTTP server and
  // the browser do that); open tunnels still hold their own references.
  server.unref();

  const { port } = server.address() as net.AddressInfo;
  return {
    url: `socks5://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((closed) => {
        for (const client of clients) client.destroy();
        server.close(() => closed());
      }),
  };
}
