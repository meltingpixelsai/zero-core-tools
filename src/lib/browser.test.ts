import { test } from "node:test";
import assert from "node:assert/strict";
import { browserChannel, browserConfig, config } from "../config.js";
import {
  BROWSER_UNAVAILABLE,
  BrowserUnavailableError,
  LAUNCH_RETRY_AFTER_MS,
  WEBRTC_NO_DIRECT_UDP,
  browserLaunchOptions,
  createSharedBrowser,
  type BrowserHandle,
} from "./browser.js";

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
    args: ["--disable-dev-shm-usage", "--webrtc-ip-handling-policy=disable_non_proxied_udp"],
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

test("WebRTC is kept from sending UDP around the proxy on every launch, sandboxed or not, on either build", () => {
  // The proxy setting covers TCP only. The end-to-end test in egress-proxy.test.ts shows what this flag stops.
  assert.equal(WEBRTC_NO_DIRECT_UDP, "--webrtc-ip-handling-policy=disable_non_proxied_udp");
  for (const sandbox of [true, false]) {
    for (const channel of ["chrome", "chromium"] as const) {
      const args = browserLaunchOptions("socks5://127.0.0.1:1", sandbox, channel).args ?? [];
      assert.equal(args.filter((a) => a.includes("webrtc")).join(" "), WEBRTC_NO_DIRECT_UDP, `sandbox ${String(sandbox)}, ${channel}`);
    }
  }
});

// ── The shared browser holder ────────────────────────────────

/** A stand-in browser that records whether it was closed. */
function fakeBrowser(id: number): BrowserHandle & { id: number; connected: boolean; closed: number } {
  const b = {
    id,
    connected: true,
    closed: 0,
    isConnected: () => b.connected,
    close: async () => {
      b.closed++;
      b.connected = false;
    },
  };
  return b;
}

/** A launcher under the test's control: each call waits until the test resolves or rejects it. */
function manualLauncher() {
  type Fake = ReturnType<typeof fakeBrowser>;
  const pending: Array<{ resolve: (b: Fake) => void; reject: (e: Error) => void }> = [];
  const launched: Fake[] = [];
  let calls = 0;
  return {
    launch: () =>
      new Promise<Fake>((resolve, reject) => {
        calls++;
        pending.push({ resolve, reject });
      }),
    calls: () => calls,
    launched,
    succeed: () => {
      const b = fakeBrowser(launched.length + 1);
      launched.push(b);
      pending.shift()?.resolve(b);
      return b;
    },
    fail: (message: string) => pending.shift()?.reject(new Error(message)),
  };
}

test("calls that arrive while the browser is launching share that one launch", async () => {
  // Before, each call that found no browser launched its own, and all but the last were never closed.
  const l = manualLauncher();
  const shared = createSharedBrowser({ launch: l.launch, log: () => undefined });
  const calls = [shared.get(), shared.get(), shared.get()];
  assert.equal(l.calls(), 1, "three calls at once start one launch");
  const b = l.succeed();
  assert.deepEqual(await Promise.all(calls), [b, b, b]);
  assert.equal(await shared.get(), b);
  assert.equal(l.calls(), 1, "a connected browser is reused");
});

test("a failed launch is logged in full and reaches every waiting caller as the fixed message only", async () => {
  const l = manualLauncher();
  const logs: string[] = [];
  const shared = createSharedBrowser({ launch: l.launch, log: (line) => logs.push(line), now: () => 1_000 });
  const calls = [shared.get(), shared.get()];
  const secret = "browserType.launch: Failed to launch /opt/google/chrome/chrome --proxy-server=socks5://127.0.0.1:41234";
  l.fail(secret);
  for (const call of calls) {
    await assert.rejects(call, (err: unknown) => {
      assert.ok(err instanceof BrowserUnavailableError);
      assert.equal(err.message, BROWSER_UNAVAILABLE);
      assert.ok(!String(err.stack).includes("/opt/google"), "the cause must not ride along in the error");
      assert.equal((err as { cause?: unknown }).cause, undefined);
      return true;
    });
  }
  assert.equal(logs.length, 1);
  assert.ok(logs[0]?.includes(secret), "the server log keeps the cause");
  assert.ok(!BROWSER_UNAVAILABLE.includes("/"), "the caller's message names no path");
});

test("after a failed launch, calls inside the retry window are refused without launching; after it, one launch is tried", async () => {
  const l = manualLauncher();
  let clock = 50_000;
  const shared = createSharedBrowser({ launch: l.launch, log: () => undefined, now: () => clock });
  const first = shared.get();
  l.fail("no chrome");
  await assert.rejects(first, BrowserUnavailableError);
  clock += LAUNCH_RETRY_AFTER_MS - 1;
  await assert.rejects(shared.get(), BrowserUnavailableError);
  await assert.rejects(shared.get(), BrowserUnavailableError);
  assert.equal(l.calls(), 1, "no launch inside the window");
  clock += 1;
  const retry = shared.get();
  assert.equal(l.calls(), 2, "the window is over: one new launch");
  const b = l.succeed();
  assert.equal(await retry, b);
  // A success clears the failure: a later disconnect relaunches at once, with no window to wait out.
  b.connected = false;
  const again = shared.get();
  assert.equal(l.calls(), 3);
  const b2 = l.succeed();
  assert.equal(await again, b2);
});

test("a launcher that throws instead of returning a promise is handled like any failed launch, and does not wedge the holder", async () => {
  let calls = 0;
  let clock = 0;
  const shared = createSharedBrowser<BrowserHandle>({
    launch: () => {
      calls++;
      if (calls === 1) throw new Error("sync failure");
      return Promise.resolve(fakeBrowser(calls));
    },
    log: () => undefined,
    now: () => clock,
  });
  await assert.rejects(shared.get(), BrowserUnavailableError);
  clock += LAUNCH_RETRY_AFTER_MS;
  assert.equal((await shared.get()).isConnected(), true);
  assert.equal(calls, 2);
});

test("a browser that has disconnected is replaced by one launch, and the old one is closed", async () => {
  const l = manualLauncher();
  const shared = createSharedBrowser({ launch: l.launch, log: () => undefined });
  const first = shared.get();
  const b1 = l.succeed();
  await first;
  b1.connected = false; // crashed, or killed
  const calls = [shared.get(), shared.get()];
  assert.equal(l.calls(), 2, "two calls after the crash start one launch");
  const b2 = l.succeed();
  assert.deepEqual(await Promise.all(calls), [b2, b2]);
  assert.equal(b1.closed, 1);
  assert.equal(b2.closed, 0);
});

test("close waits for a launch in flight and closes what it produced; a failed launch in flight closes cleanly", async () => {
  const l = manualLauncher();
  const shared = createSharedBrowser({ launch: l.launch, log: () => undefined });
  const getting = shared.get();
  let closed = false;
  const closing = shared.close().then(() => (closed = true));
  await new Promise((r) => setImmediate(r));
  assert.equal(closed, false, "close does not return while the launch is in flight");
  const b = l.succeed();
  await getting;
  await closing;
  assert.equal(b.closed, 1, "the browser the launch produced is closed, not left behind");

  const l2 = manualLauncher();
  const shared2 = createSharedBrowser({ launch: l2.launch, log: () => undefined });
  const failing = shared2.get();
  const closing2 = shared2.close();
  l2.fail("no chrome");
  await assert.rejects(failing, BrowserUnavailableError);
  await closing2;
  await shared2.close(); // nothing to close: no throw
});
