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
  },

  // Browser config
  browser: {
    timeout: 30_000,
    maxContentLength: 50_000,
  },
} as const;
