export type BrowserChannel = "chrome" | "chromium";

/**
 * The browser build the sandboxed launch runs (see lib/browser.ts). Only the exact name "chromium" selects the
 * build Playwright bundles; anything else, a typo included, means the host's Google Chrome.
 */
export function browserChannel(value: string | undefined): BrowserChannel {
  return value === "chromium" ? "chromium" : "chrome";
}

/**
 * Browser settings for an environment. It reads nothing but its argument, so the tests can pin what an empty or a
 * production environment gives without depending on the shell that runs them.
 */
export function browserConfig(env: Readonly<Record<string, string | undefined>>): Readonly<{
  timeout: number;
  maxContentLength: number;
  sandbox: boolean;
  channel: BrowserChannel;
}> {
  return {
    timeout: 30_000,
    maxContentLength: 50_000,
    // The browser's process sandbox is ON unless BROWSER_SANDBOX=off is set explicitly (see browser.ts).
    sandbox: env.BROWSER_SANDBOX !== "off",
    // The sandboxed launch runs the host's Google Chrome unless BROWSER_CHANNEL=chromium is set explicitly.
    channel: browserChannel(env.BROWSER_CHANNEL),
  };
}

export const config = {
  port: parseInt(process.env.PORT || "8403", 10),

  // Grok API (xAI)
  grok: {
    apiKey: process.env.XAI_API_KEY || "",
    model: "grok-4-1-fast",
    apiUrl: "https://api.x.ai/v1/chat/completions",
  },

  // x402 payment config
  payment: {
    wallet: process.env.PAYMENT_WALLET || "2MB8Gk4PebwhP6yaiiMjofHYoQvvQ8iWo3hdkUHQ1Wdq",
    facilitator: process.env.X402_FACILITATOR || "https://facilitator.payai.network",
    network: "solana" as const,
    currency: "USDC",
  },

  // Tool pricing (in USD)
  pricing: {
    scrape_url: 0.005,
    screenshot_url: 0.005,
    extract_structured_data: 0.02,
    review_code: 0.03,
    generate_content: 0.05,
    analyze_sentiment: 0.01,
    search_web: 0.01,
  },

  // Browser config
  browser: browserConfig(process.env),
} as const;
