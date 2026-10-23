import { test } from "node:test";
import assert from "node:assert/strict";
import { Agent, createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { installGracefulShutdown } from "./graceful-shutdown.js";

// Real HTTP servers on 127.0.0.1. No signal handler is installed here
// (signals: []); calling the returned shutdown function stands in for SIGINT.

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
}

function get(port: number, path: string, agent?: Agent): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, agent: agent ?? false }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function exitRecorder() {
  const codes: number[] = [];
  let resolve!: () => void;
  const exited = new Promise<void>((r) => (resolve = r));
  return {
    codes,
    exited,
    exit: (code: number) => {
      codes.push(code);
      resolve();
    },
  };
}

/** A server whose /slow requests wait until release() is called. */
function slowServer() {
  let release!: () => void;
  const released = new Promise<void>((r) => (release = r));
  let arrived!: () => void;
  const slowArrived = new Promise<void>((r) => (arrived = r));
  const server = createServer(async (req, res) => {
    if (req.url === "/slow") {
      arrived();
      await released;
    }
    res.end("done");
  });
  return { server, release, slowArrived };
}

test("a request in flight is answered before the process exits, and new connections are refused", async () => {
  const { server, release, slowArrived } = slowServer();
  const port = await listen(server);
  const exit = exitRecorder();
  const shutdown = installGracefulShutdown(server, { graceMs: 10_000, signals: [], log: () => {}, exit: exit.exit });

  const inFlight = get(port, "/slow");
  await slowArrived;
  shutdown("TEST");

  await assert.rejects(get(port, "/fast"), { code: "ECONNREFUSED" });
  assert.deepEqual(exit.codes, [], "exited while a request was in flight");

  release();
  assert.deepEqual(await inFlight, { status: 200, body: "done" });
  await exit.exited;
  assert.deepEqual(exit.codes, [0]);
});

test("a keep-alive connection is closed once its request in flight is answered", async () => {
  const { server, release, slowArrived } = slowServer();
  const port = await listen(server);
  const agent = new Agent({ keepAlive: true });
  const exit = exitRecorder();
  const shutdown = installGracefulShutdown(server, { graceMs: 10_000, signals: [], log: () => {}, exit: exit.exit });

  const inFlight = get(port, "/slow", agent);
  await slowArrived;
  shutdown("TEST");
  release();
  assert.deepEqual(await inFlight, { status: 200, body: "done" });
  const answered = Date.now();
  await exit.exited;
  assert.ok(Date.now() - answered < 2000, "the answered keep-alive connection held the shutdown open");
  assert.deepEqual(exit.codes, [0]);
  agent.destroy();
});

test("with nothing in flight the process exits at once, idle keep-alive connections included", async () => {
  const server = createServer((_req, res) => res.end("ok"));
  const port = await listen(server);
  const agent = new Agent({ keepAlive: true });
  assert.deepEqual(await get(port, "/", agent), { status: 200, body: "ok" });
  const exit = exitRecorder();
  const shutdown = installGracefulShutdown(server, { graceMs: 10_000, signals: [], log: () => {}, exit: exit.exit });

  const started = Date.now();
  shutdown("TEST");
  await exit.exited;
  assert.ok(Date.now() - started < 2000, "an idle keep-alive connection held the shutdown open");
  assert.deepEqual(exit.codes, [0]);
  agent.destroy();
});

test("the process exits after the grace period when a request never finishes", async () => {
  let arrived!: () => void;
  const hangArrived = new Promise<void>((r) => (arrived = r));
  const server = createServer(() => arrived()); // never answers
  const port = await listen(server);
  const exit = exitRecorder();
  const logs: string[] = [];
  const shutdown = installGracefulShutdown(server, { graceMs: 300, signals: [], log: (m) => logs.push(m), exit: exit.exit });

  const hanging = get(port, "/hang").catch((err: NodeJS.ErrnoException) => err.code);
  await hangArrived;
  const started = Date.now();
  shutdown("TEST");
  shutdown("TEST again"); // a second signal starts nothing new
  await exit.exited;
  assert.ok(Date.now() - started >= 250, "exited before the grace period");
  assert.deepEqual(exit.codes, [0]);
  assert.match(logs.at(-1) ?? "", /grace period over/);

  server.closeAllConnections();
  assert.equal(await hanging, "ECONNRESET");
  assert.deepEqual(exit.codes, [0], "exited twice");
});

test("SIGINT and SIGTERM start the shutdown by default", () => {
  const before = { SIGINT: process.listeners("SIGINT"), SIGTERM: process.listeners("SIGTERM") };
  const codes: number[] = [];
  const logs: string[] = [];
  installGracefulShutdown(createServer(), { log: (m) => logs.push(m), exit: (code) => codes.push(code) });
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    const added = process.listeners(signal).filter((listener) => !before[signal].includes(listener));
    assert.equal(added.length, 1, signal);
    process.removeListener(signal, added[0]);
  }
  assert.deepEqual(codes, []);
  assert.deepEqual(logs, []);
});
