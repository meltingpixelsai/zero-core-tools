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
