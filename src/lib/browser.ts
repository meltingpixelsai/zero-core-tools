import { chromium, type Browser, type LaunchOptions, type Page } from "playwright";
import { config } from "../config.js";
import { startEgressProxy, type EgressProxy } from "./egress-proxy.js";
import { assertUrlSafe, isUrlSafe } from "./ssrf.js";

let browser: Browser | null = null;
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
 */
export function browserLaunchOptions(proxyServer: string): LaunchOptions {
  return {
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    proxy: { server: proxyServer, bypass: "<-loopback>" },
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  };
}

/** Get or create the shared Playwright browser instance */
async function getBrowser(): Promise<Browser> {
  if (!browser || !browser.isConnected()) {
    const proxy = await getEgressProxy();
    browser = await chromium.launch(browserLaunchOptions(proxy.url));
  }
  return browser;
}

/** Create a new page with standard config. Caller MUST close the page when done. */
export async function createPage(options?: {
  blockMedia?: boolean;
  width?: number;
  height?: number;
}): Promise<Page> {
  const b = await getBrowser();
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
  if (browser) {
    await browser.close();
    browser = null;
  }
}
