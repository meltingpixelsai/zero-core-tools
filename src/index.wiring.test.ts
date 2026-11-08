import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Starts the real server (src/index.ts through tsx) on a free 127.0.0.1 port, with no .env, a stand-in
// facilitator and a temporary claims folder, and checks that the request guard and the graceful shutdown are
// wired in. Windows has no POSIX signals for child processes, so a preload turns an IPC "sigint" message into
// what SIGINT does on Linux: the process's SIGINT listeners run, or with none it exits at once (130).

const PRELOAD = `process.on("message", (m) => {
  if (m !== "sigint") return;
  if (process.listenerCount("SIGINT") > 0) process.emit("SIGINT", "SIGINT");
  else process.exit(130);
});
process.channel?.unref();
`;

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

/** One request; "no answer" if nothing comes back within 3 s. */
function send(
  port: number,
  method: string,
  urlPath: string,
  body?: string,
  extraHeaders: Record<string, string> = {},
): Promise<{ status: number | "no answer"; allow?: string; text?: string }> {
  return new Promise((resolve) => {
    const base = body === undefined ? {} : { "content-type": "application/json", accept: "application/json, text/event-stream" };
    const headers = { ...base, ...extraHeaders };
    const req = http.request({ host: "127.0.0.1", port, method, path: urlPath, agent: false, headers }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (d: string) => (text += d));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, allow: res.headers.allow, text }));
    });
    req.setTimeout(3000, () => {
      req.destroy();
      resolve({ status: "no answer" });
    });
    req.on("error", () => resolve({ status: "no answer" }));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/**
 * A raw HTTP/1.1 request: the head, then body chunks (write errors ignored), and the status code of the response's
 * status line, or "no answer" within 5 s. For requests the server refuses before reading the whole body, where a
 * normal client can see a reset before the response.
 */
function rawStatus(port: number, head: string, chunks: string[] = []): Promise<number | "no answer"> {
  return new Promise((resolve) => {
    let got = "";
    let done = false;
    const status = () => {
      const m = got.match(/^HTTP\/1\.1 (\d{3})/);
      return m && m[1] !== undefined ? Number(m[1]) : "no answer";
    };
    const sock = net.connect(port, "127.0.0.1", () => {
      sock.write(head);
      for (const c of chunks) {
        if (sock.destroyed) break;
        sock.write(c, () => undefined);
      }
    });
    const finish = (v: number | "no answer") => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(v);
    };
    const timer = setTimeout(() => finish(status()), 5000);
    sock.on("data", (d: Buffer) => {
      got += d.toString("latin1");
      if (status() !== "no answer") finish(status());
    });
    sock.on("error", () => finish(status()));
    sock.on("close", () => finish(status()));
  });
}

test("the server answers what mcp-handler would not, and drains on SIGINT", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zc-wiring-"));
  const preload = path.join(tmp, "sigint-ipc.mjs");
  fs.writeFileSync(preload, PRELOAD);
  const facilitator = http.createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/supported")) {
      return res.end(JSON.stringify({ kinds: [{ x402Version: 1, scheme: "exact", network: "solana", extra: { feePayer: "FeePayer111111111111111111111111111111111111" } }] }));
    }
    res.statusCode = 404;
    res.end("{}");
  });
  await new Promise<void>((r) => facilitator.listen(0, "127.0.0.1", r));
  const port = await freePort();
  const env: NodeJS.ProcessEnv = {
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
  };
  const child = spawn(process.execPath, ["--import", "tsx", "--import", pathToFileURL(preload).href, "src/index.ts"], {
    cwd: process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  let out = "";
  child.stdout?.on("data", (d) => (out += d));
  child.stderr?.on("data", (d) => (out += d));
  const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
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

  const put = await send(port, "PUT", "/mcp", "{}");
  assert.equal(put.status, 405);
  assert.equal(put.allow, "GET, POST, DELETE");
  assert.equal((await send(port, "POST", "/mcp", "[".repeat(5000) + "]".repeat(5000))).status, 400);
  const cancel = JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } });
  assert.equal((await send(port, "POST", "/mcp", cancel)).status, 202);
  // Size, charset, shape and element limits (GHSA-f897-62hf-6gxq, GHSA-46jr-4wx8-v453), answered before mcp-handler
  // sees the request.
  const head = (extra: string) => `POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n${extra}\r\n`;
  // A chunked body over 1 MiB: the counting reader stops past the cap (64 KiB chunks, 18 of them).
  const piece = "a".repeat(65_536);
  const chunked = [...Array.from({ length: 18 }, () => `10000\r\n${piece}\r\n`), "0\r\n\r\n"];
  assert.equal(await rawStatus(port, head("Transfer-Encoding: chunked\r\n"), chunked), 413);
  // A declared Content-Length over 1 MiB, refused from the headers alone (no body is sent).
  assert.equal(await rawStatus(port, head("Content-Length: 2000000\r\n")), 413);
  assert.equal(await rawStatus(port, head("Content-Length: 00000000000000002000000\r\n")), 413);
  const wide = JSON.stringify({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "x", arguments: { items: Array.from({ length: 2_000 }, () => 0) } } });
  const wideRes = await send(port, "POST", "/mcp", wide);
  assert.equal(wideRes.status, 400);
  assert.match(wideRes.text ?? "", /more than 1000 array elements and object keys/);
  // The same call wrapped in a JSON string, which mcp-handler would unwrap into the real message.
  const wrapped = await send(port, "POST", "/mcp", JSON.stringify(wide));
  assert.equal(wrapped.status, 400);
  assert.match(wrapped.text ?? "", /must be a JSON-RPC message or a batch of messages/);
  // A charset the SDK would decode differently.
  const utf7 = await send(port, "POST", "/mcp", wide, { "content-type": "application/json; charset=utf-7" });
  assert.equal(utf7.status, 415);
  // Positive control: an ordinary initialize still reaches mcp-handler (rebuilt from the checked text) and answers.
  const init = JSON.stringify({ jsonrpc: "2.0", id: 9, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "wiring-test", version: "1" } } });
  const initRes = await send(port, "POST", "/mcp", init);
  assert.equal(initRes.status, 200, initRes.text);
  assert.match(initRes.text ?? "", /"serverInfo"/);
  assert.equal((await send(port, "GET", "/health")).status, 200);

  child.send("sigint");
  const code = await Promise.race([exited, new Promise<"timeout">((r) => setTimeout(() => r("timeout"), 15_000))]);
  assert.equal(code, 0, "exit code; output:\n" + out.slice(-600));
  assert.match(out, /\[shutdown\] SIGINT: not accepting new connections/);
  assert.match(out, /\[shutdown\] no requests in flight; exiting/);
});
