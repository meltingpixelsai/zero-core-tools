import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { encodePayment } from "x402/schemes";

// Starts the real server (src/index.ts through tsx) with a browser that cannot start, and sends a browser tool a
// payment the stand-in facilitator calls valid. The call must be refused before the payment is settled, and the
// caller must not be handed the launch error. The browser is made unstartable the same way on every machine: the
// bundled build is asked for by name (BROWSER_CHANNEL=chromium) and Playwright is pointed at an empty folder, so
// there is no executable to run. The URL is an address literal, so nothing is resolved, and nothing leaves 127.0.0.1.
// A second test, off unless SSRF_E2E_BROWSER is set, runs the same path with a browser that does start.

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

/** POST one JSON-RPC body to /mcp; the full response text, or "no answer" after `timeoutMs`. */
function rpc(port: number, body: string, timeoutMs = 20_000): Promise<string> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path: "/mcp",
        agent: false,
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => (text += chunk));
        res.on("end", () => resolve(text));
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      resolve("no answer");
    });
    req.on("error", () => resolve("no answer"));
    req.end(body);
  });
}

// A transaction shaped like an x402 "exact" Solana payment (as in index.isolation.test.ts): fee payer and paying
// wallet sign; one SPL Token TransferChecked whose authority is the paying wallet.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(text: string): Buffer {
  let n = 0n;
  for (const ch of text) n = n * 58n + BigInt(B58.indexOf(ch));
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  return Buffer.from(out);
}
const k32 = (s: string) => createHash("sha256").update(s).digest();
function paymentToken(seed: string): string {
  const keys = [k32("fee-payer"), k32("preflight-payer"), k32("source"), k32("destination"), k32("mint"), b58decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")];
  const data = Buffer.concat([Buffer.from([12]), Buffer.alloc(8), Buffer.from([6])]);
  const message = Buffer.concat([Buffer.from([0x80, 2, 0, 2, keys.length]), ...keys, k32("blockhash-" + seed), Buffer.from([1, 5, 4, 2, 4, 3, 1, data.length]), data, Buffer.from([0])]);
  const transaction = Buffer.concat([Buffer.from([2]), Buffer.alloc(128), message]).toString("base64");
  return encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction } } as Parameters<typeof encodePayment>[0]);
}

interface Started {
  /** verify and settle requests the stand-in facilitator has had. */
  seen: { verify: number; settle: number };
  /** Everything the server has written to stdout and stderr so far. */
  out: () => string;
  call: (name: string, args: Record<string, unknown>, token?: string) => Promise<string>;
}

/**
 * Starts a stand-in facilitator that calls every payment valid and settles it, and the server pointed at it, with
 * `browserEnv(tmp)` added to the server's environment (tmp is a folder removed after the test).
 */
async function startServer(t: TestContext, browserEnv: (tmp: string) => NodeJS.ProcessEnv): Promise<Started> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zc-preflight-"));
  const seen = { verify: 0, settle: 0 };
  const facilitator = http.createServer((req, res) => {
    req.resume();
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/supported")) {
      return res.end(JSON.stringify({ kinds: [{ x402Version: 1, scheme: "exact", network: "solana", extra: { feePayer: "FeePayer111111111111111111111111111111111111" } }] }));
    }
    if (req.url?.startsWith("/verify")) {
      seen.verify++;
      return res.end(JSON.stringify({ isValid: true, payer: "Payer1111" }));
    }
    if (req.url?.startsWith("/settle")) {
      seen.settle++;
      return res.end(JSON.stringify({ success: true, transaction: "sig-preflight", network: "solana", payer: "Payer1111" }));
    }
    res.statusCode = 404;
    res.end("{}");
  });
  await new Promise<void>((r) => facilitator.listen(0, "127.0.0.1", r));
  const port = await freePort();
  const child = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: process.cwd(),
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      HOME: process.env.HOME,
      USERPROFILE: process.env.USERPROFILE,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      PORT: String(port),
      NODE_ENV: "production",
      X402_FACILITATOR: `http://127.0.0.1:${(facilitator.address() as net.AddressInfo).port}`,
      PAYMENT_WALLET: "Recipient11111111111111111111111111111111111",
      X402_CLAIMS_DIR: path.join(tmp, "claims"),
      // Set, and empty: dotenv leaves a variable that is already set alone, so a .env beside the checkout cannot
      // hand a tool a real key.
      XAI_API_KEY: "",
      ...browserEnv(tmp),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout?.on("data", (d) => (out += d));
  child.stderr?.on("data", (d) => (out += d));
  t.after(() => {
    if (child.exitCode === null) child.kill();
    facilitator.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  const started = Date.now();
  while (!/running on port/i.test(out)) {
    assert.ok(Date.now() - started < 60_000, "the server did not start:\n" + out.slice(-600));
    assert.equal(child.exitCode, null, "the server exited at startup:\n" + out.slice(-600));
    await new Promise((r) => setTimeout(r, 200));
  }
  const call = (name: string, args: Record<string, unknown>, token?: string) =>
    rpc(port, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args, ...(token ? { _meta: { "x402/payment": token } } : {}) } }));
  return { seen, out: () => out, call };
}

test("a browser tool whose browser cannot start refuses a valid payment before settling it, and keeps the cause to the log", async (t) => {
  const { seen, out, call } = await startServer(t, (tmp) => {
    const noBrowsers = path.join(tmp, "no-browsers");
    fs.mkdirSync(noBrowsers);
    return { BROWSER_CHANNEL: "chromium", PLAYWRIGHT_BROWSERS_PATH: noBrowsers };
  });
  // An address literal, so nothing is resolved. It is a public address, so the URL check passes; it is never
  // contacted, because no browser starts.
  const url = "http://93.184.216.34/";

  // No payment: the price is quoted as before, and the readiness check does not run (no launch is attempted).
  const quote = await call("scrape_url", { url });
  assert.match(quote, /PAYMENT_REQUIRED/);
  assert.doesNotMatch(out(), /\[browser\] launch/, "an unpaid call must not set off a browser launch");

  const token = paymentToken(`preflight-${Date.now()}`);
  for (const [name, args] of [
    ["scrape_url", { url }],
    ["screenshot_url", { url }],
    ["extract_structured_data", { url, schema_description: "anything" }],
  ] as const) {
    const before = { ...seen };
    const answer = await call(name, args, token);
    assert.notEqual(answer, "no answer", `${name}: no answer`);
    assert.match(answer, /Browser unavailable\. No payment was taken\. Try again later\./, `${name}: ${answer.slice(0, 300)}`);
    assert.doesNotMatch(answer, /x402\/payment-response/, `${name}: the refusal must not carry a payment response`);
    assert.doesNotMatch(answer, /Executable|playwright|no-browsers|chrome-|\.exe|launch/i, `${name}: the launch error reached the caller`);
    assert.equal(seen.verify, before.verify + 1, `${name}: the payment is verified first`);
    assert.equal(seen.settle, before.settle, `${name}: the payment must not be settled`);
  }
  // The same payment was accepted for verification three times: each refusal released its claim.
  assert.equal(seen.settle, 0);
  assert.match(out(), /\[browser\] launch failed; callers are told/);
  // The launch failed for the reason this test arranged, and the log names it: the words the answers were checked
  // for above are really in the cause.
  assert.match(out(), /Executable doesn't exist at .*no-browsers/, "the log names the cause:\n" + out().slice(-800));
  assert.match(out(), /not ready, payment not settled, tool not run/);
  assert.equal(out().split("[browser] launch failed").length - 1, 1, "three calls inside the retry window make one launch attempt");

  // Control: a paid tool with no browser behind it still settles and runs (it then stops at its missing API key,
  // before any network call), so the refusals above came from the readiness check and not from the stand-ins.
  const control = await call("analyze_sentiment", { text: "control" }, paymentToken(`control-${Date.now()}`));
  assert.equal(seen.settle, 1, "the control tool's payment settles");
  assert.match(control, /x402\/payment-response/);
  assert.match(control, /XAI_API_KEY not configured/, "the control tool ran, and stopped before calling its upstream");
});

// End-to-end, with a browser that does start: the readiness check launches it, the payment then settles, and the
// tool returns the page. Needs a local Chromium-family browser and the public internet (the server refuses
// anything but a public address), so it runs only when SSRF_E2E_BROWSER names the channel, as in
// egress-proxy.test.ts. CHROME_DEVEL_SANDBOX and PLAYWRIGHT_BROWSERS_PATH are passed on if the shell sets them.
const e2eBrowser = process.env.SSRF_E2E_BROWSER;
test(
  "browser: with a browser that starts, two paid calls at once share one launch, both settle, and the page comes back",
  { skip: e2eBrowser ? false : "set SSRF_E2E_BROWSER=chrome|chromium|headless-shell to run (needs the public internet)" },
  async (t) => {
    const { seen, out, call } = await startServer(t, () => ({
      // "headless-shell" is the BROWSER_SANDBOX=off launch (no channel), as in egress-proxy.test.ts.
      ...(e2eBrowser === "headless-shell" ? { BROWSER_SANDBOX: "off" } : { BROWSER_CHANNEL: e2eBrowser }),
      ...(process.env.CHROME_DEVEL_SANDBOX ? { CHROME_DEVEL_SANDBOX: process.env.CHROME_DEVEL_SANDBOX } : {}),
      ...(process.env.PLAYWRIGHT_BROWSERS_PATH ? { PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH } : {}),
    }));
    const url = "https://example.com/";
    const answers = await Promise.all([
      call("scrape_url", { url }, paymentToken(`e2e-a-${Date.now()}`)),
      call("scrape_url", { url }, paymentToken(`e2e-b-${Date.now()}`)),
    ]);
    for (const answer of answers) {
      assert.match(answer, /Example Domain/, answer.slice(0, 400));
      assert.match(answer, /x402\/payment-response/);
    }
    assert.equal(seen.verify, 2);
    assert.equal(seen.settle, 2);
    assert.equal(out().split("[browser] launched ").length - 1, 1, "one launch for two calls at once:\n" + out().slice(-600));
    assert.doesNotMatch(out(), /\[browser\] launch failed/);
  },
);
