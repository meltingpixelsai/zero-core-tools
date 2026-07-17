import "dotenv/config";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { createMcpPaidHandler } from "mcpay/handler";
import { z } from "zod";
import { config } from "./config.js";
import { registerDiscoveryRoutes } from "./discovery.js";
import { landingHtml, devHtml } from "./landing.js";
import { scrapeUrl, screenshotUrl, extractStructuredData } from "./tools/scraping.js";
import { reviewCode } from "./tools/code-review.js";
import { generateContent } from "./tools/content.js";
import { analyzeSentiment } from "./tools/sentiment.js";
import { searchWeb } from "./tools/search.js";

// ── Shared tool callback helpers ─────────────────────────────

function toolResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function toolError(err: unknown) {
  return {
    content: [{ type: "text" as const, text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
    isError: true as const,
  };
}

// ── Free tool data ───────────────────────────────────────────

function listTools() {
  return {
    server: "zero-core-tools",
    version: "1.0.0",
    payment: { network: config.payment.network, currency: config.payment.currency, method: "x402" },
    tools: [
      { name: "list_tools", description: "List all tools with pricing", price: "FREE" },
      { name: "health", description: "Server status and payment config", price: "FREE" },
      { name: "scrape_url", description: "Scrape any URL, return cleaned text", price: "$0.005" },
      { name: "screenshot_url", description: "Full-page screenshot as base64 PNG", price: "$0.005" },
      { name: "extract_structured_data", description: "Scrape URL + AI extract structured JSON", price: "$0.02" },
      { name: "review_code", description: "Security + quality code review", price: "$0.03" },
      { name: "generate_content", description: "Generate blog posts, docs, descriptions", price: "$0.05" },
      { name: "analyze_sentiment", description: "Sentiment analysis + entity extraction", price: "$0.01" },
      { name: "search_web", description: "Search the web via Google, return organic results", price: "$0.01" },
    ],
  };
}

function health() {
  return {
    status: "ok",
    server: "zero-core-tools",
    version: "1.0.0",
    uptime: Math.floor(process.uptime()),
    payment: {
      network: config.payment.network,
      currency: config.payment.currency,
      wallet: config.payment.wallet,
      facilitator: config.payment.facilitator,
      method: "x402",
    },
    capabilities: ["web-scraping", "screenshots", "structured-extraction", "code-review", "content-generation", "sentiment-analysis", "web-search"],
  };
}

// ── Tool registration ────────────────────────────────────────
// Server typed as `any` because mcpay bundles its own @modelcontextprotocol/sdk
// version, making its McpServer type incompatible at compile time.

/* eslint-disable @typescript-eslint/no-explicit-any */

function registerFreeTools(server: any): void {
  server.tool(
    "list_tools",
    "List all available Zero Core Tools with pricing and input requirements. Use this for discovery.",
    {},
    async () => toolResult(listTools())
  );

  server.tool(
    "health",
    "Check Zero Core Tools server status, uptime, and payment network configuration.",
    {},
    async () => toolResult(health())
  );
}

// ── x402 Paid Handler ────────────────────────────────────────

const paidHandler = createMcpPaidHandler(
  (server) => {
    registerFreeTools(server);

    // ── Scraping tools ──

    server.paidTool(
      "scrape_url",
      "Scrape any URL and return cleaned text content. Powered by Playwright headless browser. Returns title, content, word count.",
      "$0.005",
      {
        url: z.string().url().describe("URL to scrape"),
        max_length: z.number().min(100).max(50000).optional().describe("Max content length in chars (default: 10000)"),
      },
      {},
      async ({ url, max_length }: { url: string; max_length?: number }) => {
        try {
          return toolResult(await scrapeUrl(url, max_length ?? 10_000));
        } catch (err) {
          return toolError(err);
        }
      }
    );

    server.paidTool(
      "screenshot_url",
      "Take a full-page screenshot of any URL. Returns base64-encoded PNG image.",
      "$0.005",
      {
        url: z.string().url().describe("URL to screenshot"),
        full_page: z.boolean().optional().describe("Capture full page scroll height (default: true)"),
        width: z.number().min(320).max(3840).optional().describe("Viewport width in pixels (default: 1280)"),
        height: z.number().min(240).max(2160).optional().describe("Viewport height in pixels (default: 720)"),
      },
      {},
      async ({ url, full_page, width, height }: { url: string; full_page?: boolean; width?: number; height?: number }) => {
        try {
          return toolResult(await screenshotUrl(url, full_page ?? true, width ?? 1280, height ?? 720));
        } catch (err) {
          return toolError(err);
        }
      }
    );

    server.paidTool(
      "extract_structured_data",
      "Scrape a URL then use AI to extract structured JSON data matching your schema description. Combines Playwright scraping with Grok LLM extraction.",
      "$0.02",
      {
        url: z.string().url().describe("URL to scrape"),
        schema_description: z.string().describe("Description of the data to extract and desired JSON structure. Example: 'Extract all product names and prices as {products: [{name, price}]}'"),
      },
      {},
      async ({ url, schema_description }: { url: string; schema_description: string }) => {
        try {
          return toolResult(await extractStructuredData(url, schema_description));
        } catch (err) {
          return toolError(err);
        }
      }
    );

    // ── Code review ──

    server.paidTool(
      "review_code",
      "AI-powered security and quality code review. Analyzes for vulnerabilities, anti-patterns, performance issues, and best practices. Returns issues with severity, suggestions, and an overall score.",
      "$0.03",
      {
        code: z.string().describe("Source code to review"),
        language: z.string().optional().describe("Programming language (auto-detected if omitted)"),
        focus: z.string().optional().describe("Focus area: security, quality, performance, or all (default: all)"),
      },
      {},
      async ({ code, language, focus }: { code: string; language?: string; focus?: string }) => {
        try {
          return toolResult(await reviewCode(code, language, focus));
        } catch (err) {
          return toolError(err);
        }
      }
    );

    // ── Content generation ──

    server.paidTool(
      "generate_content",
      "Generate high-quality written content. Supports blog posts, product descriptions, documentation, social posts, and emails. Customizable tone, length, and keywords.",
      "$0.05",
      {
        type: z.enum(["blog_post", "product_description", "documentation", "social_post", "email"]).describe("Content type"),
        topic: z.string().describe("Topic or subject to write about"),
        tone: z.enum(["professional", "casual", "technical", "friendly"]).optional().describe("Writing tone (default: professional)"),
        length: z.enum(["short", "medium", "long"]).optional().describe("Target length (default: medium)"),
        keywords: z.string().optional().describe("Comma-separated keywords to include"),
      },
      {},
      async ({ type, topic, tone, length, keywords }: { type: string; topic: string; tone?: string; length?: string; keywords?: string }) => {
        try {
          return toolResult(await generateContent(type, topic, tone, length, keywords));
        } catch (err) {
          return toolError(err);
        }
      }
    );

    // ── Sentiment analysis ──

    server.paidTool(
      "analyze_sentiment",
      "Analyze sentiment of text with entity extraction, confidence scores, and key phrase identification. Returns positive/negative/neutral/mixed with detailed breakdown.",
      "$0.01",
      {
        text: z.string().describe("Text to analyze for sentiment"),
      },
      {},
      async ({ text }: { text: string }) => {
        try {
          return toolResult(await analyzeSentiment(text));
        } catch (err) {
          return toolError(err);
        }
      }
    );

    // ── Web search ──

    server.paidTool(
      "search_web",
      "Search the web via Google and return organic results with titles, links, and snippets. Optionally returns answer box if available.",
      "$0.01",
      {
        query: z.string().min(1).describe("Search query"),
        num_results: z.number().min(1).max(50).optional().describe("Number of results to return (default: 10)"),
      },
      {},
      async ({ query, num_results }: { query: string; num_results?: number }) => {
        try {
          return toolResult(await searchWeb(query, num_results ?? 10));
        } catch (err) {
          return toolError(err);
        }
      }
    );
  },
  {
    facilitator: {
      url: config.payment.facilitator as `${string}://${string}`,
    },
    recipient: {
      svm: {
        address: config.payment.wallet,
        isTestnet: false,
      },
    },
  },
  {
    serverInfo: { name: "zero-core-tools", version: "1.1.0" },
  },
  {
    maxDuration: 300,
    verboseLogs: process.env.NODE_ENV !== "production",
  }
);

// ── Hono HTTP Server ─────────────────────────────────────────

const app = new Hono();

// Health + pricing endpoints (outside MCP, for monitoring/discovery)
app.get("/health", (c) => c.json(health()));
app.get("/pricing", (c) => c.json(listTools()));

// Agent discovery routes
registerDiscoveryRoutes(app);

// Landing pages for human visitors
app.get("/", (c) => c.html(landingHtml()));
app.get("/dev", (c) => c.html(devHtml()));

// MCP handler — x402 only (no API key auth needed)
app.all("*", async (c) => {
  return paidHandler(c.req.raw);
});

// ── Start ────────────────────────────────────────────────────

serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`Zero Core Tools MCP server running on port ${config.port}`);
  console.log(`  MCP endpoint: http://localhost:${config.port}/`);
  console.log(`  Health: http://localhost:${config.port}/health`);
  console.log(`  Pricing: http://localhost:${config.port}/pricing`);
  console.log(`  Auth: x402 USDC only`);
  console.log(`  Payment wallet: ${config.payment.wallet}`);
  console.log(`  Facilitator: ${config.payment.facilitator}`);
  console.log(`  Network: ${config.payment.network} (${config.payment.currency})`);
});
