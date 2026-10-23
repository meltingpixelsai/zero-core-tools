import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { BEFORE_EXIT_TIMEOUT_MS, SHUTDOWN_GRACE_MS } from "./graceful-shutdown.js";

const require = createRequire(import.meta.url);
const { apps } = require("../../ecosystem.config.cjs") as { apps: Array<Record<string, unknown>> };
const app = apps[0];

test("the process manager waits longer than the shutdown grace and cleanup before it kills", () => {
  assert.equal(apps.length, 1);
  const killTimeout = app.kill_timeout;
  assert.ok(typeof killTimeout === "number" && killTimeout > SHUTDOWN_GRACE_MS + BEFORE_EXIT_TIMEOUT_MS, `kill_timeout ${String(killTimeout)}`);
});

test("the Tools server is signalled alone, so its browser calls can drain", { skip: app.name !== "harvey-tools" }, () => {
  assert.equal(app.treekill, false);
});

test("the V8 heap cap leaves room for calls in flight and for memory outside the heap", () => {
  const cap = String(app.node_args ?? "").match(/--max-old-space-size=(\d+)/);
  assert.ok(cap, "no --max-old-space-size in node_args");
  const limit = String(app.max_memory_restart ?? "").match(/^(\d+)M$/);
  assert.ok(limit, "max_memory_restart is not given in megabytes");
  const capMb = Number(cap[1]);
  const limitMb = Number(limit[1]);
  // Measured under a burst on 10-23: live data is about 40-60 MB plus about 0.1 MB per call in flight, and a 160 MB
  // cap aborted at about 1,100 calls with no drain. RSS runs about 75-100 MB above the heap (young generation, code,
  // native memory), so the limit must sit well above the cap or a burst still restarts the server.
  assert.ok(capMb >= 192, `heap cap ${capMb} MB is too small for a burst of calls in flight`);
  assert.ok(limitMb - capMb >= 128, `heap cap ${capMb} MB leaves too little room under the ${limitMb} MB limit`);
});
