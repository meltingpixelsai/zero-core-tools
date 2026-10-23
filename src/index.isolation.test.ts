import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { encodePayment } from "x402/schemes";

// Starts the real server (src/index.ts through tsx) and sends two clients' requests with the same JSON-RPC id at
// the same time: a paid call whose payment check a stand-in facilitator holds for 1.5 s, and a free tools/list.
// mcp-handler's one shared transport routed answers by id alone, so the paid call's answer was lost and the call
// never answered. Each must get its own answer. No real payment: the facilitator refuses it, and nothing leaves
// 127.0.0.1.

const ARGS: Record<string, Record<string, unknown>> = {
  analyze_sentiment: { text: "isolation test" },
  get_service_quality: { service_id: "isolation-test" },
  get_spending_report: { agent_id: "isolation-test", period: "day" },
};

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
function rpc(port: number, body: string, timeoutMs = 8000): Promise<string> {
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

// A transaction shaped like an x402 "exact" Solana payment: fee payer and paying wallet sign; one SPL Token
// TransferChecked whose authority is the paying wallet. The facilitator stand-in refuses it.
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
  const keys = [k32("fee-payer"), k32("isolation-payer"), k32("source"), k32("destination"), k32("mint"), b58decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")];
  const data = Buffer.concat([Buffer.from([12]), Buffer.alloc(8), Buffer.from([6])]);
  const message = Buffer.concat([Buffer.from([0x80, 2, 0, 2, keys.length]), ...keys, k32("blockhash-" + seed), Buffer.from([1, 5, 4, 2, 4, 3, 1, data.length]), data, Buffer.from([0])]);
  const transaction = Buffer.concat([Buffer.from([2]), Buffer.alloc(128), message]).toString("base64");
  return encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction } } as Parameters<typeof encodePayment>[0]);
}

test("two clients' requests with the same id each get their own answer", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zc-isolation-"));
  const facilitator = http.createServer((req, res) => {
    req.resume();
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/supported")) {
      return res.end(JSON.stringify({ kinds: [{ x402Version: 1, scheme: "exact", network: "solana", extra: { feePayer: "FeePayer111111111111111111111111111111111111" } }] }));
    }
    if (req.url?.startsWith("/verify")) {
      return setTimeout(() => res.end(JSON.stringify({ isValid: false, invalidReason: "insufficient_funds" })), 1500);
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

  const listed = await rpc(port, JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }));
  const tool = Object.keys(ARGS).find((name) => listed.includes(`"name":"${name}"`));
  assert.ok(tool, "no known paid tool in tools/list:\n" + listed.slice(0, 300));

  const paidCall = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: ARGS[tool], _meta: { "x402/payment": paymentToken(`isolation-${Date.now()}`) } } });
  const paid = rpc(port, paidCall);
  await new Promise((r) => setTimeout(r, 400)); // the paid call now waits on the facilitator
  const free = await rpc(port, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }));
  const paidAnswer = await paid;

  assert.match(free, /"tools":\[/, "the free client did not get its tool list");
  assert.doesNotMatch(free, /x402\/error/, "the free client got the paid call's answer");
  assert.notEqual(paidAnswer, "no answer", "the paid call got no answer");
  assert.match(paidAnswer, /x402\/error|"isError":true/, "the paid client did not get its own answer");
  assert.doesNotMatch(paidAnswer, /"tools":\[/, "the paid client got the free call's answer");
});
