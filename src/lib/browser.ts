import { chromium, type Browser, type LaunchOptions, type Page } from "playwright";
import { config, type BrowserChannel } from "../config.js";
import { startEgressProxy, type EgressProxy } from "./egress-proxy.js";
import { assertUrlSafe, isUrlSafe } from "./ssrf.js";

let egressProxy: Promise<EgressProxy> | null = null;

/** Start (once) the SSRF egress proxy every browser connection goes through. */
function getEgressProxy(): Promise<EgressProxy> {
  if (!egressProxy) {
    const starting = startEgressProxy();
    egressProxy = starting;
    starting.catch(() => {
      if (egressProxy === starting) egressProxy = null; // retry on next launch
    });
  }
  return egressProxy;
}

/**
 * Keeps WebRTC from sending UDP around the egress proxy. A proxy setting covers
 * the browser's TCP connections only: with Chromium's default policy a page's
 * script can open an RTCPeerConnection and have the browser send STUN packets
 * straight from the host to any address and port the page names, a private or
 * link-local one included, which the SOCKS proxy never sees. With the policy
 * "disable_non_proxied_udp" WebRTC sends UDP only through a proxy that can
 * carry it, which a SOCKS proxy as Chromium uses it cannot, so no WebRTC UDP
 * leaves the host; WebRTC's TCP connections go through the proxy like any
 * other.
 *
 * The policy has two switches, and each build obeys only one of them (measured
 * on Linux, 2026-11-11: Google Chrome 157.0.8103.50, and Playwright 1.64.1's
 * bundled 156.0.8078.4 as the full build and as chrome-headless-shell):
 * - Google Chrome and the bundled full build obey --webrtc-ip-handling-policy
 *   and ignore the other;
 * - chrome-headless-shell, which the BROWSER_SANDBOX=off launch runs, obeys
 *   --force-webrtc-ip-handling-policy and ignores the other.
 * Every launch gets both. The end-to-end test in egress-proxy.test.ts shows,
 * for the build it is pointed at, the packets arriving without the switches
 * and none with them: run it again when the browser's major version changes,
 * because a switch a build stops obeying fails silently.
 */
export const WEBRTC_NO_DIRECT_UDP = "--webrtc-ip-handling-policy=disable_non_proxied_udp";
export const WEBRTC_NO_DIRECT_UDP_HEADLESS_SHELL = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp";
export const WEBRTC_NO_DIRECT_UDP_ARGS: readonly string[] = [WEBRTC_NO_DIRECT_UDP, WEBRTC_NO_DIRECT_UDP_HEADLESS_SHELL];

/**
 * Launch options for the shared browser. All browser traffic leaves through
 * the SSRF egress proxy (egress-proxy.ts), which checks every connection —
 * including redirect hops, which page.route never sees. "<-loopback>" stops
 * Chromium's implicit proxy bypass for localhost and link-local addresses
 * (127.0.0.0/8, ::1, 169.254.0.0/16, fe80::/10), so those are refused by the
 * proxy rather than connected to directly; it is set explicitly rather than
 * left to Playwright's default.
 *
 * Playwright's own signal handlers are off: by default a launch installs a
 * SIGINT handler that closes the browser and exits the process at once, which
 * would cut off the paid calls the graceful shutdown (graceful-shutdown.ts)
 * waits for. index.ts closes the browser after the drain instead.
 *
 * Chromium's process sandbox is ON: the renderer that parses a caller's page
 * runs in its own PID and network namespaces under seccomp-bpf, so a renderer
 * bug does not become code running as the server's account. Playwright does
 * not add --no-sandbox when chromiumSandbox is true, and a launch that cannot
 * set the sandbox up fails instead of running unsandboxed; the tools then
 * return an error for that call.
 *
 * The sandboxed launch runs the host's Google Chrome (channel "chrome") by
 * default, not the build Playwright bundles (Chrome for Testing, which
 * Playwright installs under the name "chromium"). Callers choose the pages
 * this browser loads, so it needs browser security fixes promptly: Google
 * ships them in Chrome first, and a Playwright release bundles them later (on
 * 2026-11-09 Chrome 157.0.8103.50 fixed a bug exploited in the wild while the
 * Playwright version locked here, 1.64.1, bundled 156.0.8078.4). If Google
 * Chrome is not installed, or will not start, the launch fails and the tools
 * return an error for that call; it does not fall back to the bundled build.
 * The browser tools start the browser before a call's payment is settled
 * (browserReady, below), so a call refused for this reason is not charged; a
 * browser that dies after that check and cannot be restarted still fails a
 * call that has been paid for.
 * Keeping the host's Chrome package current is then part of running this
 * server, and so is restarting the server after a Chrome upgrade: it keeps one
 * browser process until that process ends, and logs the version at each launch.
 * BROWSER_CHANNEL=chromium selects the bundled build by name: the full build
 * (not chrome-headless-shell), for a host without Google Chrome.
 *
 * On Ubuntu 24.04 unprivileged user namespaces are restricted by AppArmor.
 * Ubuntu ships an AppArmor profile (/etc/apparmor.d/chrome, package apparmor)
 * that lets the Google Chrome binary at /opt/google/chrome/chrome create them,
 * so Chrome runs its namespace sandbox there. The bundled build has no such
 * profile: its namespace sandbox cannot start, and it needs the setuid sandbox
 * helper named by CHROME_DEVEL_SANDBOX in the environment (ecosystem.config.cjs
 * names the root-owned helper installed by Google Chrome) or its launch fails.
 * A host that allows user namespaces needs no helper.
 *
 * BROWSER_SANDBOX=off keeps the old unsandboxed launch for places that cannot
 * sandbox at all (the Dockerfile runs as root in a container); the server warns
 * once when it is off. It is never set in production.
 *
 * WebRTC is held to the proxy as well, on the sandboxed and the unsandboxed
 * launch (WEBRTC_NO_DIRECT_UDP_ARGS, above).
 */
export function browserLaunchOptions(
  proxyServer: string,
  sandbox: boolean = config.browser.sandbox,
  channel: BrowserChannel = config.browser.channel,
): LaunchOptions {
  return {
    headless: true,
    ...(sandbox
      ? { chromiumSandbox: true, channel, args: ["--disable-dev-shm-usage", ...WEBRTC_NO_DIRECT_UDP_ARGS] }
      : {
          chromiumSandbox: false,
          args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", ...WEBRTC_NO_DIRECT_UDP_ARGS],
        }),
    proxy: { server: proxyServer, bypass: "<-loopback>" },
    timeout: LAUNCH_TIMEOUT_MS,
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  };
}

/**
 * What a caller is told when the browser cannot be started. The cause (a
 * missing or broken Chrome, the sandbox, the egress proxy) is written to the
 * server's log only: Playwright's launch error carries the executable's path,
 * the whole command line and the browser's own output, which a caller has no
 * use for and should not be handed.
 */
export const BROWSER_UNAVAILABLE = "Browser unavailable: the page could not be loaded. Try again later.";

/** The same, for a call refused before its payment was settled (the browser tools' preflight in index.ts). */
export const BROWSER_UNAVAILABLE_UNPAID = "Browser unavailable. No payment was taken. Try again later.";

export class BrowserUnavailableError extends Error {
  constructor() {
    super(BROWSER_UNAVAILABLE);
    this.name = "BrowserUnavailableError";
  }
}

/** After a failed launch, calls inside this window are refused without another launch attempt. */
export const LAUNCH_RETRY_AFTER_MS = 15_000;

/**
 * How long one launch may take. Playwright's own default is three minutes. A launch can run while a caller's payment
 * is verified and not yet settled (browserReady, below), and a signed payment stays valid for about a minute, so a
 * browser that has not started by now is treated as one that cannot start.
 */
export const LAUNCH_TIMEOUT_MS = 30_000;

const LOG_HEAD_CHARS = 1_000;
const LOG_TAIL_CHARS = 5_000;

// C0 and C1 control characters, DEL, and the two Unicode line separators. Built from code points, so that no
// editor or tool can turn an escape written here into the character itself.
const CONTROL_CHARACTERS = new RegExp(`[\\x00-\\x1f\\x7f-\\x9f${String.fromCharCode(0x2028, 0x2029)}]`, "g");

/**
 * An error's text for the server log: on ONE line, and cut in the middle when it is long.
 *
 * One line, with every control character written as an escape, because part of the text can come from a caller's
 * page: an exception thrown by the page's own script is copied into Playwright's error. Logged as it is, such a
 * page could add lines of its own to the log (a made-up payment line, say) or send terminal escape codes to
 * whoever reads it.
 *
 * Cut in the middle, because Playwright's launch and closed-browser errors put the command line first and the
 * browser's own output, which names the cause, near the end (before the stack frames): both ends are kept.
 */
export function errorForLog(err: unknown): string {
  let detail: string;
  try {
    detail = err instanceof Error ? err.stack || err.message : String(err);
  } catch {
    detail = "(an error that cannot be turned into text)";
  }
  if (detail.length > LOG_HEAD_CHARS + LOG_TAIL_CHARS) {
    const cut = detail.length - LOG_HEAD_CHARS - LOG_TAIL_CHARS;
    detail = `${detail.slice(0, LOG_HEAD_CHARS)} [... ${cut} characters cut ...] ${detail.slice(-LOG_TAIL_CHARS)}`;
  }
  return detail.replace(CONTROL_CHARACTERS, (ch) =>
    ch === "\n" ? "\\n" : ch === "\r" ? "\\r" : ch === "\t" ? "\\t" : `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/**
 * Whether a browser tool's error says the browser went away during the call. Playwright then appends the browser's
 * log to the error, and that log is what tells an operator why (a crash, the out-of-memory killer, a missing
 * library). Other failed calls (a timeout, a refused or unreachable address) are the caller's business and are not
 * logged: their text holds the caller's URL.
 */
export function browserWentAway(err: unknown): boolean {
  return err instanceof Error && /\nBrowser logs:|browser has been closed|Target crashed/i.test(err.message);
}

const CALLER_MESSAGE_CHARS = 300;

/**
 * What a caller is told when a browser tool fails: the first line of the error, and no more. Playwright appends the
 * call log to its errors, and to a "browser has been closed" error the browser's log, which starts with the
 * executable's path and the whole command line (the proxy's port and the profile folder included). The first line
 * is the part a caller can use ("page.goto: Timeout 30000ms exceeded.", "URL not allowed ...").
 *
 * This removes what Playwright appends. It does not rewrite the first line: an error whose first line itself
 * quotes something (an upstream API's error body, in grok-client.ts) still passes that on, up to the length cap.
 */
export function callerErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return (message.split("\n", 1)[0] ?? "").slice(0, CALLER_MESSAGE_CHARS);
}

/** The part of a browser the holder below needs; Playwright's Browser satisfies it. */
export interface BrowserHandle {
  isConnected(): boolean;
  close(): Promise<void>;
}

export interface SharedBrowserDeps<B extends BrowserHandle> {
  launch: () => Promise<B>;
  now?: () => number;
  log?: (line: string) => void;
  retryAfterMs?: number;
}

export interface SharedBrowser<B extends BrowserHandle> {
  /** The connected browser, launching it if there is none. Rejects with BrowserUnavailableError and nothing else. */
  get(): Promise<B>;
  /**
   * Close the browser, waiting first for a launch that is in flight when close is called. It is not final: a get()
   * after it launches again. The server calls it once, at shutdown: after the calls in flight have drained, or with
   * some still running when the shutdown grace runs out (one of those can then launch again; Playwright's own exit
   * handler ends that browser with the process).
   */
  close(): Promise<void>;
}

/**
 * Holds the one browser every call shares.
 *
 * - One launch at a time: calls that arrive while a launch is in flight wait
 *   for that launch. (Before, each of them saw "no browser yet" and launched
 *   its own, and all but the last were never closed.)
 * - A failed launch is logged here and reaches callers as BrowserUnavailableError.
 * - After a failed launch, calls inside retryAfterMs are refused at once, so a
 *   host whose browser cannot start is not made to try again on every call.
 * - A browser that has disconnected (crashed or killed) is replaced at the
 *   next call.
 */
export function createSharedBrowser<B extends BrowserHandle>(deps: SharedBrowserDeps<B>): SharedBrowser<B> {
  // A clock that only moves forward: the retry window must not stretch when the wall clock is set back.
  const now = deps.now ?? (() => performance.now());
  const log = deps.log ?? ((line: string) => console.error(line));
  const retryAfterMs = deps.retryAfterMs ?? LAUNCH_RETRY_AFTER_MS;
  let current: B | null = null;
  let launching: Promise<B> | null = null;
  let failedAt: number | null = null;

  async function launchOnce(): Promise<B> {
    try {
      const launched = await deps.launch();
      current = launched;
      failedAt = null;
      return launched;
    } catch (err) {
      failedAt = now();
      log(`[browser] launch failed; callers are told "${BROWSER_UNAVAILABLE}": ${errorForLog(err)}`);
      throw new BrowserUnavailableError();
    }
  }

  function get(): Promise<B> {
    if (current?.isConnected()) return Promise.resolve(current);
    if (launching) return launching;
    if (failedAt !== null && now() - failedAt < retryAfterMs) return Promise.reject(new BrowserUnavailableError());
    const stale = current;
    current = null;
    // A disconnected browser's process is normally gone already, and closing it then does nothing.
    if (stale) void stale.close().catch(() => undefined);
    const attempt = launchOnce();
    launching = attempt;
    const done = (): void => {
      if (launching === attempt) launching = null;
    };
    attempt.then(done, done);
    return attempt;
  }

  async function close(): Promise<void> {
    const pending = launching;
    if (pending) await pending.catch(() => undefined);
    const open = current;
    current = null;
    if (open) await open.close();
  }

  return { get, close };
}

let warnedSandboxOff = false;

/** One real launch: the egress proxy first, then the browser with the production launch options. */
async function launchBrowser(): Promise<Browser> {
  if (!config.browser.sandbox && !warnedSandboxOff) {
    warnedSandboxOff = true;
    console.warn("[browser] BROWSER_SANDBOX=off: Chromium runs WITHOUT its process sandbox");
  }
  const proxy = await getEgressProxy();
  const options = browserLaunchOptions(proxy.url);
  const launched = await chromium.launch(options);
  // One line per launch, so the log shows which build and version is really serving calls. The build name is read
  // from the options this launch was given, and the version is the one the browser itself reports.
  console.log(`[browser] launched ${options.channel ?? "bundled headless shell, no sandbox"} ${launched.version()}`);
  return launched;
}

const sharedBrowser = createSharedBrowser<Browser>({ launch: launchBrowser });

/**
 * Whether the browser is running, starting it if it is not. The browser tools
 * ask this once a caller's payment has been verified and before it is settled
 * (index.ts), so a host whose browser cannot start refuses the call instead of
 * taking the payment and then failing. Never throws.
 */
export async function browserReady(): Promise<boolean> {
  try {
    await sharedBrowser.get();
    return true;
  } catch {
    return false;
  }
}

/** Create a new page with standard config. Caller MUST close the page when done. */
export async function createPage(options?: {
  blockMedia?: boolean;
  width?: number;
  height?: number;
}): Promise<Page> {
  const b = await sharedBrowser.get();
  const page = await b.newPage({
    viewport: {
      width: options?.width ?? 1280,
      height: options?.height ?? 720,
    },
    userAgent:
      "Mozilla/5.0 (compatible; ZeroCoreTools/1.0; +https://tools.rugslayer.com) AppleWebKit/537.36 Chrome/120.0.0.0",
  });

  const blockMedia = options?.blockMedia !== false;

  // Registered UNCONDITIONALLY (screenshots pass blockMedia:false, which
  // previously meant no interceptor at all): requests this handler sees — the
  // main navigation and subresources — are SSRF-checked so an <img src>
  // pointing at an internal host fails fast. Playwright does NOT call route
  // handlers for redirect hops, so this is not the enforcement point for
  // redirects: the egress proxy (browserLaunchOptions) is. Media is
  // additionally dropped here when blockMedia is set. A per-page cache keeps a
  // busy page from re-resolving the same host on every asset.
  const safeHostCache = new Map<string, Promise<boolean>>();
  await page.route("**/*", async (route) => {
    const request = route.request();
    if (blockMedia && ["image", "font", "media", "stylesheet"].includes(request.resourceType())) {
      return route.abort();
    }
    const url = request.url();
    let key: string;
    try {
      key = new URL(url).host;
    } catch {
      return route.abort("blockedbyclient");
    }
    let verdict = safeHostCache.get(key);
    if (!verdict) {
      verdict = isUrlSafe(url);
      safeHostCache.set(key, verdict);
    }
    return (await verdict) ? route.continue() : route.abort("blockedbyclient");
  });

  page.setDefaultTimeout(config.browser.timeout);
  return page;
}

/** Navigate to URL and wait for content to settle */
export async function navigateTo(page: Page, url: string): Promise<void> {
  // Fail fast with a clear error before the browser touches the network. The
  // egress proxy re-checks every connection, including each redirect hop.
  await assertUrlSafe(url);
  await page.goto(url, { waitUntil: "networkidle", timeout: config.browser.timeout });
}

/** Extract text content from the current page */
export async function extractText(page: Page, maxLength: number): Promise<{ title: string; content: string }> {
  const title = await page.title();
  const content = await page.evaluate(() => {
    // Remove script/style/nav/footer noise
    const remove = document.querySelectorAll("script, style, nav, footer, header, aside, [role=banner], [role=navigation]");
    remove.forEach((el) => el.remove());
    return document.body?.innerText?.trim() || "";
  });

  return {
    title,
    content: content.slice(0, maxLength),
  };
}

/** Gracefully close the browser (for cleanup) */
export async function closeBrowser(): Promise<void> {
  await sharedBrowser.close();
}
