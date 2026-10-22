import { test } from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns";
import http from "node:http";
import net from "node:net";
import { startEgressProxy, type EgressProxy } from "./egress-proxy.js";
import { __setResolverForTests, resolvePublicAddresses } from "./ssrf.js";

// Every server here listens on 127.0.0.1 and every refused destination is
// refused before any connect, so the suite makes no outbound network call.

const REP_SUCCEEDED = 0x00;
const REP_NOT_ALLOWED = 0x02;
const REP_COMMAND_NOT_SUPPORTED = 0x07;

/** Local TCP echo server that counts the connections it receives. */
async function startEchoServer(): Promise<{ port: number; connections: () => number; close: () => Promise<void> }> {
  let count = 0;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((s) => {
    count++;
    sockets.add(s);
    s.on("error", () => s.destroy());
    s.pipe(s);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return {
    port: (server.address() as net.AddressInfo).port,
    connections: () => count,
    close: () =>
      new Promise<void>((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}

/** Byte reader over a socket that waits for exactly n bytes. */
function byteReader(socket: net.Socket): (n: number) => Promise<Buffer> {
  let buf = Buffer.alloc(0);
  let done = false;
  let wake: (() => void) | null = null;
  socket.on("data", (c: Buffer) => {
    buf = Buffer.concat([buf, c]);
    wake?.();
  });
  for (const ev of ["end", "close"]) {
    socket.on(ev, () => {
      done = true;
      wake?.();
    });
  }
  return async (n) => {
    while (buf.length < n) {
      if (done) throw new Error(`socket closed after ${buf.length}/${n} bytes`);
      await new Promise<void>((r) => (wake = r));
      wake = null;
    }
    const out = buf.subarray(0, n);
    buf = buf.subarray(n);
    return out;
  };
}

const portBytes = (port: number): number[] => [port >> 8, port & 0xff];
const domainRequest = (host: string, port: number, cmd = 0x01): Buffer =>
  Buffer.from([0x05, cmd, 0x00, 0x03, host.length, ...Buffer.from(host, "latin1"), ...portBytes(port)]);
const ipv4Request = (ip: string, port: number): Buffer =>
  Buffer.from([0x05, 0x01, 0x00, 0x01, ...ip.split(".").map(Number), ...portBytes(port)]);
const ipv6Request = (hextets: number[], port: number): Buffer =>
  Buffer.from([0x05, 0x01, 0x00, 0x04, ...hextets.flatMap((h) => [h >> 8, h & 0xff]), ...portBytes(port)]);

/** Runs a SOCKS5 no-auth handshake + one request; returns the reply code and the open socket. */
async function socks(proxy: EgressProxy, request: Buffer): Promise<{ rep: number; socket: net.Socket; read: (n: number) => Promise<Buffer> }> {
  const socket = net.connect(Number(new URL(proxy.url).port), "127.0.0.1");
  socket.on("error", () => {});
  const read = byteReader(socket);
  socket.write(Buffer.from([0x05, 0x01, 0x00]));
  assert.deepEqual([...(await read(2))], [0x05, 0x00], "no-auth method accepted");
  socket.write(request);
  const reply = await read(10);
  assert.equal(reply[0], 0x05);
  return { rep: reply[1], socket, read };
}

test("refuses loopback, metadata and private destinations in every address form, without connecting", async () => {
  const target = await startEchoServer();
  const proxy = await startEgressProxy();
  try {
    const p = target.port;
    const cases: Array<[string, Buffer]> = [
      ["ipv4 127.0.0.1", ipv4Request("127.0.0.1", p)],
      ["domain 127.0.0.1", domainRequest("127.0.0.1", p)],
      ["domain localhost", domainRequest("localhost", p)],
      ["ipv6 ::1", ipv6Request([0, 0, 0, 0, 0, 0, 0, 1], p)],
      ["domain [::1]", domainRequest("[::1]", p)],
      ["ipv6 ::ffff:127.0.0.1", ipv6Request([0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001], p)],
      ["ipv4 169.254.169.254 (metadata)", ipv4Request("169.254.169.254", 80)],
      ["domain 169.254.169.254 (metadata)", domainRequest("169.254.169.254", 80)],
      ["ipv6 ::ffff:169.254.169.254 (metadata)", ipv6Request([0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe], 80)],
      ["ipv4 10.0.0.5", ipv4Request("10.0.0.5", 80)],
      ["ipv4 0.0.0.0", ipv4Request("0.0.0.0", p)],
      ["empty domain", domainRequest("", p)],
    ];
    for (const [name, request] of cases) {
      const { rep, socket } = await socks(proxy, request);
      socket.destroy();
      assert.equal(rep, REP_NOT_ALLOWED, name);
    }
    assert.equal(target.connections(), 0, "no refused request reached the loopback service");
  } finally {
    await proxy.close();
    await target.close();
  }
});

test("refuses a host whose DNS answers include a private address (rebinding record shape)", async () => {
  const proxy = await startEgressProxy();
  try {
    __setResolverForTests(async () => [{ address: "93.184.216.34" }, { address: "127.0.0.1" }]);
    const { rep, socket } = await socks(proxy, domainRequest("rebind.example", 80));
    socket.destroy();
    assert.equal(rep, REP_NOT_ALLOWED);
  } finally {
    __setResolverForTests(null);
    await proxy.close();
  }
});

test("refuses BIND and UDP ASSOCIATE (only CONNECT is proxied)", async () => {
  const proxy = await startEgressProxy();
  try {
    for (const cmd of [0x02, 0x03]) {
      const { rep, socket } = await socks(proxy, domainRequest("example.com", 80, cmd));
      socket.destroy();
      assert.equal(rep, REP_COMMAND_NOT_SUPPORTED, `cmd ${cmd}`);
    }
  } finally {
    await proxy.close();
  }
});

test("tunnels an allowed destination, connecting only to the vetted address (no second DNS lookup)", async () => {
  const target = await startEchoServer();
  // Stand-in for a public host: the policy vets "public.test" to the local echo
  // server; every other host gets the production policy.
  const proxy = await startEgressProxy(async (host) =>
    host === "public.test" ? ["127.0.0.1"] : resolvePublicAddresses(host),
  );
  // Any fallback to Node's own resolver for the name would show up here (and
  // fail, rather than reach the network).
  const realLookup = dns.lookup;
  let nodeLookups = 0;
  (dns as { lookup: unknown }).lookup = (...args: unknown[]) => {
    nodeLookups++;
    const cb = args[args.length - 1] as (err: Error) => void;
    process.nextTick(() => cb(Object.assign(new Error("lookup disabled in test"), { code: "ENOTFOUND" })));
  };
  try {
    const { rep, socket, read } = await socks(proxy, domainRequest("public.test", target.port));
    assert.equal(rep, REP_SUCCEEDED);
    socket.write("ping");
    assert.equal((await read(4)).toString(), "ping");
    socket.destroy();
    assert.equal(target.connections(), 1);
    assert.equal(nodeLookups, 0, "upstream connect must use the vetted address, not re-resolve");
  } finally {
    (dns as { lookup: unknown }).lookup = realLookup;
    await proxy.close();
    await target.close();
  }
});

// End-to-end: the finding's exploit against a real browser launched with the
// production launch options. Needs a local Chromium-family browser, so it runs
// only when SSRF_E2E_BROWSER names one: "chromium" (Playwright's bundled
// build) or a channel such as "msedge" / "chrome".
const e2eBrowser = process.env.SSRF_E2E_BROWSER;
test(
  "browser: a 302 from an allowed host to loopback is refused at the redirect hop",
  { skip: e2eBrowser ? false : "set SSRF_E2E_BROWSER=chromium|msedge|chrome to run" },
  async () => {
    const { chromium } = await import("playwright");
    const { browserLaunchOptions } = await import("./browser.js");

    let secretHits = 0;
    const secret = http.createServer((_req, res) => {
      secretHits++;
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<body>INTERNAL-SECRET</body>");
    });
    const servers: http.Server[] = [secret];
    const listen = async (s: http.Server): Promise<number> => {
      await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
      return (s.address() as net.AddressInfo).port;
    };
    const secretPort = await listen(secret);

    // The attacker's "public" server: a page, an iframe page, and a redirect.
    const evil = http.createServer((req, res) => {
      if (req.url === "/r") {
        res.writeHead(302, { location: `http://127.0.0.1:${secretPort}/latest/meta-data/` });
        res.end();
      } else if (req.url === "/frame") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(`<body>FRAME-PAGE<iframe src="http://public.test:${evilPort}/r"></iframe></body>`);
      } else {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<body>PUBLIC-OK</body>");
      }
    });
    servers.push(evil);
    const evilPort = await listen(evil);

    const proxy = await startEgressProxy(async (host) =>
      host === "public.test" ? ["127.0.0.1"] : resolvePublicAddresses(host),
    );
    const browser = await chromium.launch({
      ...browserLaunchOptions(proxy.url),
      ...(e2eBrowser === "chromium" ? {} : { channel: e2eBrowser }),
    });
    try {
      // Interception on, as createPage has it: the first hop is route-allowed,
      // and the redirect hop never reaches this handler.
      const routed: string[] = [];
      const visit = async (url: string): Promise<string> => {
        const page = await browser.newPage();
        try {
          await page.route("**/*", (route) => {
            routed.push(route.request().url());
            return route.continue();
          });
          await page.goto(url, { waitUntil: "load", timeout: 15_000 });
          return await page.evaluate(() => document.body?.innerText ?? "");
        } finally {
          await page.close();
        }
      };
      const refusedByProxy = /net::ERR_(SOCKS_CONNECTION_FAILED|PROXY_CONNECTION_FAILED|TUNNEL_CONNECTION_FAILED)/;

      // Positive control: traffic flows through the proxy ("public.test" only
      // resolves there).
      assert.match(await visit(`http://public.test:${evilPort}/`), /PUBLIC-OK/);

      // The exploit: a 302 to loopback.
      await assert.rejects(visit(`http://public.test:${evilPort}/r`), refusedByProxy);
      assert.deepEqual(
        routed.filter((u) => u.startsWith(`http://127.0.0.1:${secretPort}/`)),
        [],
        "the redirect hop bypasses page.route, so the proxy is what stopped it",
      );

      // The same redirect inside an iframe (screenshot vector).
      assert.match(await visit(`http://public.test:${evilPort}/frame`), /FRAME-PAGE/);

      // Direct loopback navigation (as a popup/subresource would make) is
      // proxied too, not connected to directly.
      await assert.rejects(visit(`http://127.0.0.1:${secretPort}/`), refusedByProxy);
      await assert.rejects(visit(`http://localhost:${secretPort}/`), refusedByProxy);

      // Refusals do not take the proxy out of service for later requests.
      assert.match(await visit(`http://public.test:${evilPort}/`), /PUBLIC-OK/);

      assert.equal(secretHits, 0, "the internal service was never reached");
    } finally {
      await browser.close();
      await proxy.close();
      for (const s of servers) s.close();
    }
  },
);
