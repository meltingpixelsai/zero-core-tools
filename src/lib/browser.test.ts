import { test } from "node:test";
import assert from "node:assert/strict";
import { browserChannel, browserConfig, config } from "../config.js";
import {
  BROWSER_UNAVAILABLE,
  BrowserUnavailableError,
  LAUNCH_RETRY_AFTER_MS,
  LAUNCH_TIMEOUT_MS,
  browserWentAway,
  callerErrorMessage,
  errorForLog,
  WEBRTC_NO_DIRECT_UDP,
  WEBRTC_NO_DIRECT_UDP_ARGS,
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
    args: [
      "--disable-dev-shm-usage",
      "--webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ],
    proxy: { server: "http://127.0.0.1:1", bypass: "<-loopback>" },
    timeout: 30_000,
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

test("every launch, sandboxed or not, carries both WebRTC switches: the full builds obey one, the headless shell the other", () => {
  // This pins the strings only. Whether a build obeys them is what the end-to-end test in egress-proxy.test.ts
  // shows, with real packets: SSRF_E2E_BROWSER=chrome, chromium, or headless-shell (the BROWSER_SANDBOX=off launch).
  assert.deepEqual(WEBRTC_NO_DIRECT_UDP_ARGS, [
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
  ]);
  assert.equal(WEBRTC_NO_DIRECT_UDP, WEBRTC_NO_DIRECT_UDP_ARGS[0]);
  const launches = [
    browserLaunchOptions("socks5://127.0.0.1:1", true, "chrome"),
    browserLaunchOptions("socks5://127.0.0.1:1", true, "chromium"),
    browserLaunchOptions("socks5://127.0.0.1:1", false), // no channel: Playwright runs chrome-headless-shell
  ];
  for (const options of launches) {
    assert.deepEqual((options.args ?? []).filter((a) => a.includes("webrtc")), WEBRTC_NO_DIRECT_UDP_ARGS, JSON.stringify(options));
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

test("a launch is given 30 s, not Playwright's three minutes: it can run while a verified payment waits to be settled", () => {
  assert.equal(LAUNCH_TIMEOUT_MS, 30_000);
  for (const sandbox of [true, false]) {
    assert.equal(browserLaunchOptions("socks5://127.0.0.1:1", sandbox).timeout, LAUNCH_TIMEOUT_MS);
  }
});

test("a long error keeps both ends in the log: the command line first, the browser's own output last", () => {
  const head = "browserType.launch: Target page, context or browser has been closed\nBrowser logs:\n<launching> /opt/google/chrome/chrome ";
  const tail = "\n[pid=123][err] error while loading shared libraries: libnss3.so: cannot open shared object file";
  const long = new Error(head + "--flag ".repeat(3_000) + tail);
  long.stack = long.message; // no frames, so the end of the text is the end of the message
  const logged = errorForLog(long);
  assert.ok(logged.length < 6_200, `logged ${logged.length} characters`);
  assert.ok(logged.startsWith("browserType.launch: Target page, context or browser has been closed\\nBrowser logs:\\n<launching> /opt/google/chrome/chrome "));
  assert.ok(logged.endsWith("libnss3.so: cannot open shared object file"), "the cause, at the end, is kept");
  assert.match(logged, /\[\.\.\. \d+ characters cut \.\.\.\]/);
  // A short error is logged whole (on one line), a thrown non-error as its text, and nothing makes it throw.
  assert.equal(errorForLog(new Error("no chrome")).split("\\n")[0], "Error: no chrome");
  assert.equal(errorForLog("plain text"), "plain text");
  const noStack = new Error("message only");
  noStack.stack = "";
  assert.equal(errorForLog(noStack), "message only");
  assert.equal(errorForLog(Object.create(null)), "(an error that cannot be turned into text)");
});

test("an error is logged on one line: text from a caller's page cannot add log lines or send terminal codes", () => {
  // A page's own script can throw anything, and Playwright copies it into its error. The special characters are
  // built from their code points so that this file holds none of them.
  const c = (code: number) => String.fromCharCode(code);
  const hostile = new Error(
    "page.evaluate: Error: x" + c(10) + "[x402] scrape_url: failed after settlement (paid) payer=Forged tx=forged" + c(13) + c(10) +
      c(0x1b) + "[2J" + c(0x9b) + "31m" + c(0x2028) + "next" + c(9) + "tab" + c(0) + c(0x7f) + c(0x2029) + "end",
  );
  hostile.stack = hostile.message;
  const logged = errorForLog(hostile);
  for (const ch of logged) {
    const code = ch.charCodeAt(0);
    assert.ok(code >= 0x20 && !(code >= 0x7f && code <= 0x9f) && code !== 0x2028 && code !== 0x2029, "control character " + code + " survived");
  }
  const b = c(92); // one backslash
  assert.equal(
    logged,
    "page.evaluate: Error: x" + b + "n[x402] scrape_url: failed after settlement (paid) payer=Forged tx=forged" + b + "r" + b + "n" +
      b + "u001b[2J" + b + "u009b31m" + b + "u2028next" + b + "ttab" + b + "u0000" + b + "u007f" + b + "u2029end",
  );
  // A long hostile text stays one line after the cut as well.
  const longHostile = new Error(("a" + c(10)).repeat(10_000));
  longHostile.stack = longHostile.message;
  assert.equal(errorForLog(longHostile).includes(c(10)), false);
});

test("only an error that says the browser went away is logged for a browser tool; a caller's own failures are not", () => {
  assert.equal(browserWentAway(new Error("page.goto: Target page, context or browser has been closed\nBrowser logs:\n<launching> ...")), true);
  assert.equal(browserWentAway(new Error("page.goto: Target crashed \nBrowser logs:\n...")), true);
  assert.equal(browserWentAway(new Error("browserContext.newPage: Target page, context or browser has been closed")), true);
  // These hold the caller's URL, and say nothing an operator needs.
  assert.equal(browserWentAway(new Error('page.goto: Timeout 30000ms exceeded.\nCall log:\n  - navigating to "https://example.com/?token=secret"')), false);
  assert.equal(browserWentAway(new Error("page.goto: net::ERR_SOCKS_CONNECTION_FAILED at https://example.com/?token=secret")), false);
  assert.equal(browserWentAway(new Error("URL not allowed")), false);
  assert.equal(browserWentAway(new BrowserUnavailableError()), false);
  assert.equal(browserWentAway("Browser logs: thrown as text"), false);
});

test("a caller is told the first line of a browser tool's error and nothing after it", () => {
  // The shape of Playwright's error when the browser goes away during a call.
  const closed = new Error(
    "page.goto: Target page, context or browser has been closed\nBrowser logs:\n\n<launching> /opt/google/chrome/chrome --proxy-server=socks5://127.0.0.1:41234 --user-data-dir=/tmp/playwright_chromiumdev_profile-abc\n<launched> pid=4242",
  );
  assert.equal(callerErrorMessage(closed), "page.goto: Target page, context or browser has been closed");
  const timeout = new Error('page.goto: Timeout 30000ms exceeded.\nCall log:\n  - navigating to "https://example.com/", waiting until "networkidle"');
  assert.equal(callerErrorMessage(timeout), "page.goto: Timeout 30000ms exceeded.");
  // One-line errors pass unchanged, the fixed browser message included.
  assert.equal(callerErrorMessage(new Error("URL not allowed")), "URL not allowed");
  assert.equal(callerErrorMessage(new BrowserUnavailableError()), BROWSER_UNAVAILABLE);
  assert.equal(callerErrorMessage("thrown text\nsecond line"), "thrown text");
  assert.equal(callerErrorMessage(new Error("x".repeat(1_000))).length, 300);
});

test("a failed launch is logged with its cause and reaches every waiting caller as the fixed message only", async () => {
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
