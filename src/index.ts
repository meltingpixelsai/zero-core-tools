import "dotenv/config";
import type { Server } from "node:http";
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
import { assertUrlSafe } from "./lib/ssrf.js";
import { createSettleFirstPaidTools, type SettleFirstConfig } from "./lib/x402-settle-first.js";
import {
  MCP_ALLOWED_METHODS,
  MCP_MAX_BODY_BYTES,
  MCP_TOO_LARGE,
  mcpPreReadProblem,
  mcpRequestProblem,
  readCappedText,
} from "./lib/request-guard.js";
import { installGracefulShutdown } from "./lib/graceful-shutdown.js";
import { BROWSER_UNAVAILABLE_UNPAID, browserReady, callerErrorMessage, closeBrowser } from "./lib/browser.js";

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

/**
 * A browser tool's failure. The caller, who has paid, gets the first line of the error (callerErrorMessage in
 * src/lib/browser.ts says what the rest of a Playwright error can carry). The error is not logged here: its text
 * can hold the caller's URL and words chosen by the caller's page. The payment layer logs that a paid call failed,
 * and the browser module logs a launch failure and a browser that disconnected.
 */
function browserToolError(err: unknown) {
  return {
    content: [{ type: "text" as const, text: `Error: ${callerErrorMessage(err)}` }],
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

const x402Config: SettleFirstConfig = {
  facilitator: {
    url: config.payment.facilitator as `${string}://${string}`,
  },
  recipient: {
    svm: {
      address: config.payment.wallet,
      isTestnet: false,
    },
  },
};

// Paid tools take the payment (claim once, verify, settle) before they run.
// mcpay's own paidTool runs the tool first and settles after, which gives
// unsettled payments the tool for free. See src/lib/x402-settle-first.ts.
const settleFirst = createSettleFirstPaidTools(x402Config);

/** Refuse a URL the browser would refuse anyway, before the caller pays. */
async function urlPrecheck({ url }: { url: string }): Promise<string | null> {
  try {
    await assertUrlSafe(url);
    return null;
  } catch {
    return "URL not allowed: only public http(s) addresses can be fetched";
  }
}

/**
 * Refuse a browser tool's call, with the payment verified but not yet settled, when the browser cannot be started
 * (see browserReady in src/lib/browser.ts). Without it such a call was paid for and then answered with an error.
 */
async function browserPreflight(): Promise<string | null> {
  return (await browserReady()) ? null : BROWSER_UNAVAILABLE_UNPAID;
}

const browserToolOptions = { precheck: urlPrecheck, preflight: browserPreflight };

// mcp-handler serves all clients through one transport that knows a request
// only by its JSON-RPC id, and every client numbers its requests from the
// start, so two clients' calls with the same id could get each other's answers,
// a paid result included. Each request therefore gets its own handler, with its
// own server and transport; building one registers the tools (milliseconds).
const createPaidHandler = () => createMcpPaidHandler(
  (server) => {
    registerFreeTools(server);
    const paidTool = settleFirst(server);

    // ── Scraping tools ──

    paidTool(
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
          return browserToolError(err);
        }
      },
      browserToolOptions
    );

    paidTool(
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
          return browserToolError(err);
        }
      },
      browserToolOptions
    );

    paidTool(
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
          return browserToolError(err);
        }
      },
      browserToolOptions
    );

    // ── Code review ──

    paidTool(
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

    paidTool(
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

    paidTool(
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

    paidTool(
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
  x402Config,
  {
    serverInfo: { name: "zero-core-tools", version: "1.1.0" },
  },
  {
    maxDuration: 300,
    verboseLogs: process.env.NODE_ENV !== "production",
    // No Redis here: without this, an anonymous GET /sse or POST /message
    // throws "redisUrl is required" in an unawaited promise and kills the process.
    disableSse: true,
  }
);

// ── Hono HTTP Server ─────────────────────────────────────────

// A rejected promise inside the MCP transport must not stop the process and every
// in-flight call with it (a paid call cut off after settlement is charged).
process.on("unhandledRejection", (reason) => {
  console.error("[mcp] unhandled rejection, process kept alive:", reason);
});

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
// Requests mcp-handler would throw on in a promise nobody awaits (a body that is
// not JSON, or JSON too deep to re-serialize), never answer (PUT, PATCH, HEAD),
// or misroute (one client's cancellation of another client's call) are answered
// here instead. See src/lib/request-guard.ts.
app.all("*", async (c) => {
  let body: string | null = null;
  if (c.req.method === "POST") {
    // Size, charset and shape are settled here, and mcp-handler is then given exactly the text that was checked
    // (a new Request built from it), so it and the SDK parse what the guard parsed. See src/lib/request-guard.ts.
    const early = mcpPreReadProblem(c.req.header("content-length"), c.req.header("content-type"));
    if (early) return c.json({ jsonrpc: "2.0", error: { code: early.code, message: early.message }, id: null }, early.status);
    try {
      body = await readCappedText(c.req.raw.body, MCP_MAX_BODY_BYTES);
    } catch {
      return c.json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }, 400);
    }
    if (body === null) {
      return c.json({ jsonrpc: "2.0", error: { code: MCP_TOO_LARGE.code, message: MCP_TOO_LARGE.message }, id: null }, 413);
    }
  }
  const problem = mcpRequestProblem(c.req.method, body);
  if (problem?.status === 202) return c.body(null, 202);
  if (problem) {
    if (problem.status === 405) c.header("Allow", MCP_ALLOWED_METHODS);
    return c.json({ jsonrpc: "2.0", error: { code: problem.code, message: problem.message }, id: null }, problem.status);
  }
  if (body === null) return createPaidHandler()(c.req.raw);
  const headers = new Headers(c.req.raw.headers);
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  // The checked text is UTF-8 JSON: say exactly that, so no later parser can read a charset parameter differently.
  // A missing or non-JSON media type is passed on as it is, and the SDK refuses it as before.
  const mediaType = (headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType === "application/json") headers.set("content-type", "application/json");
  return createPaidHandler()(new Request(c.req.raw.url, { method: "POST", headers, body, signal: c.req.raw.signal }));
});

// ── Start ────────────────────────────────────────────────────

// serve() returns an http.Server here (no createServer option is passed).
const server = serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`Zero Core Tools MCP server running on port ${config.port}`);
  console.log(`  MCP endpoint: http://localhost:${config.port}/`);
  console.log(`  Health: http://localhost:${config.port}/health`);
  console.log(`  Pricing: http://localhost:${config.port}/pricing`);
  console.log(`  Auth: x402 USDC only`);
  console.log(`  Payment wallet: ${config.payment.wallet}`);
  console.log(`  Facilitator: ${config.payment.facilitator}`);
  console.log(`  Network: ${config.payment.network} (${config.payment.currency})`);
}) as Server;

// A stop or restart lets paid calls in flight finish, then closes the shared
// browser. See src/lib/graceful-shutdown.ts.
installGracefulShutdown(server, { beforeExit: closeBrowser });
