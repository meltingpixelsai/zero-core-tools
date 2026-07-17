import { chromium, type Browser, type Page } from "playwright";
import { config } from "../config.js";
import { assertUrlSafe, isUrlSafe } from "./ssrf.js";

let browser: Browser | null = null;

/** Get or create the shared Playwright browser instance */
async function getBrowser(): Promise<Browser> {
  if (!browser || !browser.isConnected()) {
    browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    });
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
  // previously meant no interceptor at all): every request the browser makes
  // — the main navigation, redirects, and subresources — is SSRF-checked, so
  // a redirect to http://169.254.169.254 or an <img src> pointing at an
  // internal host is aborted rather than fetched. Media is additionally
  // dropped here when blockMedia is set. A per-page cache keeps a busy page
  // from re-resolving the same host on every asset.
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
  // route interceptor (createPage) is the backstop for redirects/subresources.
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
