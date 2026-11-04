import { test } from "node:test";
import assert from "node:assert/strict";
import { browserLaunchOptions } from "./browser.js";

test("the browser launch leaves SIGINT, SIGTERM and SIGHUP to the server's graceful shutdown", () => {
  // Playwright's defaults close the browser and exit the process on these signals, cutting off paid calls.
  const options = browserLaunchOptions("http://127.0.0.1:1");
  assert.equal(options.handleSIGINT, false);
  assert.equal(options.handleSIGTERM, false);
  assert.equal(options.handleSIGHUP, false);
});

test("the browser launches with Chromium's process sandbox on, as the full Chromium build", () => {
  // A renderer bug in a caller's page must not become code running as the server's account. Playwright adds
  // --no-sandbox itself when chromiumSandbox is false, so the flag must be true and the args must not carry it.
  const options = browserLaunchOptions("http://127.0.0.1:1");
  assert.equal(options.chromiumSandbox, true);
  assert.equal(options.channel, "chromium");
  const args = options.args ?? [];
  assert.ok(!args.includes("--no-sandbox"), "--no-sandbox is in the launch args");
  assert.ok(!args.includes("--disable-setuid-sandbox"), "--disable-setuid-sandbox is in the launch args");
  assert.ok(!args.some((a) => a.startsWith("--no-zygote")), "--no-zygote is in the launch args");
});

test("the sandbox is on by default: only an explicit BROWSER_SANDBOX=off turns it off", () => {
  // The default comes from the environment at module load (config.ts); an explicit argument covers both cases here.
  assert.equal(browserLaunchOptions("http://127.0.0.1:1", true).chromiumSandbox, true);
  const off = browserLaunchOptions("http://127.0.0.1:1", false);
  assert.equal(off.chromiumSandbox, false);
  assert.ok((off.args ?? []).includes("--no-sandbox"));
  assert.equal(off.channel, undefined);
});

test("the egress proxy and the loopback rule stay in place whether the sandbox is on or off", () => {
  for (const sandbox of [true, false]) {
    const options = browserLaunchOptions("socks5://127.0.0.1:1", sandbox);
    assert.deepEqual(options.proxy, { server: "socks5://127.0.0.1:1", bypass: "<-loopback>" });
    assert.equal(options.headless, true);
    assert.ok((options.args ?? []).includes("--disable-dev-shm-usage"));
  }
});
