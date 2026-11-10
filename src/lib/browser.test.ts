import { test } from "node:test";
import assert from "node:assert/strict";
import { browserChannel, browserConfig, config } from "../config.js";
import { browserLaunchOptions } from "./browser.js";

test("the browser launch leaves SIGINT, SIGTERM and SIGHUP to the server's graceful shutdown", () => {
  // Playwright's defaults close the browser and exit the process on these signals, cutting off paid calls.
  const options = browserLaunchOptions("http://127.0.0.1:1");
  assert.equal(options.handleSIGINT, false);
  assert.equal(options.handleSIGTERM, false);
  assert.equal(options.handleSIGHUP, false);
});

test("the browser launches with its process sandbox on, as the host's Google Chrome or the bundled full build", () => {
  // A renderer bug in a caller's page must not become code running as the server's account. Playwright adds
  // --no-sandbox itself when chromiumSandbox is false, so the flag must be true and the args must not carry it.
  for (const channel of ["chrome", "chromium"] as const) {
    const options = browserLaunchOptions("http://127.0.0.1:1", true, channel);
    assert.equal(options.chromiumSandbox, true);
    assert.equal(options.channel, channel);
    const args = options.args ?? [];
    assert.ok(!args.includes("--no-sandbox"), "--no-sandbox is in the launch args");
    assert.ok(!args.includes("--disable-setuid-sandbox"), "--disable-setuid-sandbox is in the launch args");
    assert.ok(!args.some((a) => a.startsWith("--no-zygote")), "--no-zygote is in the launch args");
  }
});

test("an environment that sets nothing gives Google Chrome, sandboxed, and exactly these launch options", () => {
  // browserConfig reads only the environment it is given, so this does not depend on the shell running the tests.
  // NODE_ENV must not change the answer (production sets it in ecosystem.config.cjs), nor may an empty value.
  for (const env of [{}, { NODE_ENV: "production" }, { BROWSER_CHANNEL: "", BROWSER_SANDBOX: "" }]) {
    const settings = browserConfig(env);
    assert.equal(settings.channel, "chrome", JSON.stringify(env));
    assert.equal(settings.sandbox, true, JSON.stringify(env));
  }
  assert.equal(browserConfig({ BROWSER_CHANNEL: "chromium" }).channel, "chromium");
  assert.equal(browserConfig({ BROWSER_SANDBOX: "off" }).sandbox, false);
  // Only the exact value "off" turns the sandbox off: a value that reads like "on", or a near miss, leaves it on.
  for (const value of ["on", "1", "true", "yes", "0", "false", "no", "OFF", "Off", "off ", " off"]) {
    assert.equal(browserConfig({ BROWSER_SANDBOX: value }).sandbox, true, `BROWSER_SANDBOX=${JSON.stringify(value)}`);
  }
  // The whole options object: an added executablePath, env, ignoreDefaultArgs or argument would show up here.
  const defaults = browserConfig({});
  assert.deepEqual(browserLaunchOptions("http://127.0.0.1:1", defaults.sandbox, defaults.channel), {
    headless: true,
    chromiumSandbox: true,
    channel: "chrome",
    args: ["--disable-dev-shm-usage"],
    proxy: { server: "http://127.0.0.1:1", bypass: "<-loopback>" },
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  });
});

test("the server's browser settings equal browserConfig of the process environment, and the launch defaults equal those settings", () => {
  // True in whatever shell runs this. Run it with NODE_ENV=production as well (the deploy does) to check the
  // production environment's wiring too.
  assert.deepEqual(config.browser, browserConfig(process.env));
  assert.deepEqual(
    browserLaunchOptions("http://127.0.0.1:1"),
    browserLaunchOptions("http://127.0.0.1:1", config.browser.sandbox, config.browser.channel),
  );
});

test("the host's Google Chrome is the default: only the exact name chromium selects the bundled build", () => {
  // Google Chrome gets security fixes before a Playwright release bundles them, so a missing or mistyped
  // BROWSER_CHANNEL must not quietly select the bundled build.
  assert.equal(browserChannel(undefined), "chrome");
  assert.equal(browserChannel(""), "chrome");
  assert.equal(browserChannel("chromium"), "chromium");
  for (const value of ["Chromium", "chromium ", " chromium", "chromium-headless-shell", "msedge", "off", "0"]) {
    assert.equal(browserChannel(value), "chrome", `BROWSER_CHANNEL=${JSON.stringify(value)}`);
  }
});

test("the sandbox is on by default: only an explicit BROWSER_SANDBOX=off turns it off", () => {
  // The default comes from the environment at module load (config.ts); an explicit argument covers both cases here.
  assert.equal(browserLaunchOptions("http://127.0.0.1:1", true).chromiumSandbox, true);
  for (const channel of ["chrome", "chromium"] as const) {
    const off = browserLaunchOptions("http://127.0.0.1:1", false, channel);
    assert.equal(off.chromiumSandbox, false);
    assert.ok((off.args ?? []).includes("--no-sandbox"));
    assert.equal(off.channel, undefined);
  }
});

test("the egress proxy and the loopback rule stay in place whether the sandbox is on or off", () => {
  for (const sandbox of [true, false]) {
    const options = browserLaunchOptions("socks5://127.0.0.1:1", sandbox);
    assert.deepEqual(options.proxy, { server: "socks5://127.0.0.1:1", bypass: "<-loopback>" });
    assert.equal(options.headless, true);
    assert.ok((options.args ?? []).includes("--disable-dev-shm-usage"));
  }
});
