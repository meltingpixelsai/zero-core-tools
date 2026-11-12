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

// Starts the real server (src/index.ts through tsx) with a stand-in facilitator whose /settle answers follow a
// script, over real HTTP: a settle that is not finally answered (HTTP 503, "settlement_pending", a 502 page) must
// be asked about again with the identical body and must not be reported as failed, and an outright refusal must.
// No real payment, and nothing leaves 127.0.0.1: the paid tool stops at its missing API key.

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
function rpc(port: number, body: string, timeoutMs: number): Promise<string> {
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
      }
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
function paymentTransaction(seed: string): string {
  const keys = [k32("fee-payer"), k32("settle-payer"), k32("source"), k32("destination"), k32("mint"), b58decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")];
  const data = Buffer.concat([Buffer.from([12]), Buffer.alloc(8), Buffer.from([6])]);
  const message = Buffer.concat([Buffer.from([0x80, 2, 0, 2, keys.length]), ...keys, k32("blockhash-" + seed), Buffer.from([1, 5, 4, 2, 4, 3, 1, data.length]), data, Buffer.from([0])]);
  return Buffer.concat([Buffer.from([2]), Buffer.alloc(128), message]).toString("base64");
}
function paymentToken(seed: string): string {
  return encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: paymentTransaction(seed) } } as Parameters<typeof encodePayment>[0]);
}

/** One scripted /settle answer: an HTTP status and the response text. */
type Answer = [status: number, text: string];
const json = (value: unknown) => JSON.stringify(value);
const SIGNATURE = "4".repeat(44) + "A".repeat(44);
const SUCCESS: Answer = [200, json({ success: true, transaction: SIGNATURE, network: "solana", payer: "Payer1111" })];
const PENDING: Answer = [200, json({ success: false, errorReason: "settlement_pending", errorMessage: "still confirming", transaction: SIGNATURE, network: "solana", payer: "" })];

interface Started {
  /** The /settle answers still to give, in order; the last one repeats. Replace its content to start a new phase. */
  script: Answer[];
  /** The body of every /settle request since the script was last replaced. */
  bodies: string[];
  verifies: () => number;
  out: () => string;
  call: (token: string) => Promise<string>;
}

async function startServer(t: TestContext): Promise<Started> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zc-settle-"));
  const script: Answer[] = [SUCCESS];
  const bodies: string[] = [];
  let verifies = 0;
  const facilitator = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => (body += chunk));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/supported")) {
        return res.end(json({ kinds: [{ x402Version: 1, scheme: "exact", network: "solana", extra: { feePayer: "FeePayer111111111111111111111111111111111111" } }] }));
      }
      if (req.url?.startsWith("/verify")) {
        verifies++;
        return res.end(json({ isValid: true, payer: "Payer1111" }));
      }
      if (req.url?.startsWith("/settle")) {
        bodies.push(body);
        const [status, text] = script.length > 1 ? (script.shift() as Answer) : script[0];
        res.statusCode = status;
        if (!text.startsWith("{")) res.setHeader("content-type", "text/html");
        return res.end(text);
      }
      res.statusCode = 404;
      res.end("{}");
    });
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
      // hand the tool a real key.
      XAI_API_KEY: "",
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
  const call = (token: string) =>
    rpc(port, json({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "analyze_sentiment", arguments: { text: "settle test" }, _meta: { "x402/payment": token } } }), 30_000);
  return { script, bodies, verifies: () => verifies, out: () => out, call };
}

test("through the real server: a settle without a final answer is asked about again with the same body, and only a definite refusal offers a new payment", async (t) => {
  const { script, bodies, verifies, out, call } = await startServer(t);
  const phase = (...answers: Answer[]) => {
    script.splice(0, script.length, ...answers);
    bodies.length = 0;
  };
  const paidAndRan = (answer: string) => {
    assert.match(answer, /x402\/payment-response/, answer.slice(0, 400));
    assert.match(answer, /XAI_API_KEY not configured/, "the tool ran, and stopped before calling its upstream");
    assert.doesNotMatch(answer, /x402\/error/);
  };

  // 1. HTTP 503 with a JSON body, then "settlement_pending", then success: one call, three requests, the tool runs.
  phase([503, json({ success: false, errorReason: "service_unavailable", errorMessage: "try again", transaction: "", network: "solana", payer: "" })], PENDING, SUCCESS);
  const seed = `settle-a-${Date.now()}`;
  const started = Date.now();
  paidAndRan(await call(paymentToken(seed)));
  assert.equal(bodies.length, 3);
  assert.equal(new Set(bodies).size, 1, "every request carries the identical body");
  assert.ok(Date.now() - started >= 4500, "it waited 2 s and then 3 s between the requests");
  const sent = JSON.parse(bodies[0]) as { x402Version: number; paymentPayload: { scheme: string; network: string; payload: { transaction: string } }; paymentRequirements: { payTo: string; resource: string } };
  assert.equal(sent.x402Version, 1);
  assert.equal(sent.paymentPayload.scheme, "exact");
  assert.equal(sent.paymentPayload.payload.transaction, paymentTransaction(seed));
  assert.equal(sent.paymentRequirements.payTo, "Recipient11111111111111111111111111111111111");
  assert.equal(sent.paymentRequirements.resource, "mcp://analyze_sentiment");
  assert.equal(verifies(), 1);

  // 2. A 502 page that is not JSON, then success: the same.
  phase([502, "<html><body>Bad Gateway</body></html>"], SUCCESS);
  paidAndRan(await call(paymentToken(`settle-b-${Date.now()}`)));
  assert.equal(bodies.length, 2);
  assert.equal(new Set(bodies).size, 1);

  // 3. An outright refusal (HTTP 403 with a reason) on a payment's first request: failed, a new payment is offered,
  //    and the facilitator is asked once.
  phase([403, json({ success: false, errorReason: "free_tier_exhausted", errorMessage: "top up", transaction: "", network: "solana", payer: "" })]);
  const refused = await call(paymentToken(`settle-c-${Date.now()}`));
  assert.match(refused, /free_tier_exhausted/);
  assert.match(refused, /accepts/, "a payment that was definitely not taken is offered a new one");
  assert.doesNotMatch(refused, /x402\/payment-response/);
  assert.equal(bodies.length, 1);

  // 4. A definite failure after "settlement_pending" (the recorded outcome): failed, and released.
  phase(PENDING, [200, json({ success: false, errorReason: "invalid_transaction_state", errorMessage: "expired", transaction: SIGNATURE, network: "solana", payer: "" })]);
  const expired = await call(paymentToken(`settle-d-${Date.now()}`));
  assert.match(expired, /invalid_transaction_state/);
  assert.match(expired, /accepts/);
  assert.equal(bodies.length, 2);

  assert.match(out(), /settle failed, tool not run: reason=free_tier_exhausted/);
  assert.match(out(), /settle failed, tool not run: reason=invalid_transaction_state/);
  assert.doesNotMatch(out(), /settlement unresolved/);
});
