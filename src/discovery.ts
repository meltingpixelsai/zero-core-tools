import type { Hono } from "hono";

/** Register all agent discovery routes on the Hono app */
export function registerDiscoveryRoutes(app: Hono): void {
  app.get("/llms.txt", (c) => {
    return c.text(LLMS_TXT, 200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    });
  });

  const agentCardHandler = (c: any) =>
    c.json(AGENT_CARD, 200, {
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    });
  app.get("/.well-known/agent-card.json", agentCardHandler);
  app.get("/.well-known/agent.json", agentCardHandler);


  app.get("/.well-known/mcp.json", (c) => {
    return c.json(MCP_CARD, 200, {
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    });
  });

  app.get("/.well-known/mcp/server-card.json", (c) => {
    return c.json(MCP_CARD, 200, {
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    });
  });
}
// ── Static Content ────────────────────────────────────────────

const LLMS_TXT = `# Zero Core Tools - General-Purpose Agent Tools MCP Server

> MCP server for AI agents. Web scraping, screenshots, structured data extraction, code review, content generation, sentiment analysis.
> Pay per call with USDC via x402 micropayments. No account needed.
> Built by MeltingPixels.

## Tools (8 total, 2 free + 6 paid)
- [list_tools](https://tools.rugslayer.com/mcp): List all tools with pricing (FREE)
- [health](https://tools.rugslayer.com/mcp): Server status and payment config (FREE)
- [scrape_url](https://tools.rugslayer.com/mcp): Scrape any URL, return cleaned text ($0.005)
- [screenshot_url](https://tools.rugslayer.com/mcp): Full-page screenshot as base64 PNG ($0.005)
- [extract_structured_data](https://tools.rugslayer.com/mcp): Scrape URL + LLM extract structured JSON ($0.02)
- [review_code](https://tools.rugslayer.com/mcp): Security + quality code review ($0.03)
- [generate_content](https://tools.rugslayer.com/mcp): Generate blog posts, docs, descriptions ($0.05)
- [analyze_sentiment](https://tools.rugslayer.com/mcp): Sentiment analysis + entity extraction ($0.01)
- [search_web](https://tools.rugslayer.com/mcp): Search the web via Google ($0.01)

## Connection
- [MCP Endpoint](https://tools.rugslayer.com/mcp): Connect directly via MCP
- [npm](https://www.npmjs.com/package/@meltingpixels/zero-core-tools): @meltingpixels/zero-core-tools
- [Claude Code](https://tools.rugslayer.com/mcp): claude mcp add zero-core-tools --transport http https://tools.rugslayer.com/mcp

## Authentication
- [x402 USDC](https://tools.rugslayer.com/mcp): Pay per call on Solana, no account needed

## Pricing
- scrape_url: $0.005 USDC per call
- screenshot_url: $0.005 USDC per call
- extract_structured_data: $0.02 USDC per call
- review_code: $0.03 USDC per call
- generate_content: $0.05 USDC per call
- analyze_sentiment: $0.01 USDC per call
- search_web: $0.01 USDC per call
`;

const AGENT_CARD = {
  name: "Zero Core Tools",
  description:
    "MCP server for AI agents providing web scraping, screenshots, structured data extraction, code review, content generation, and sentiment analysis. Pay per call with USDC via x402.",
  version: "1.0.0",
  supportedInterfaces: [
    {
      url: "https://tools.rugslayer.com/mcp",
      protocolBinding: "HTTP+JSON",
      protocolVersion: "0.3",
    },
  ],
  provider: {
    organization: "MeltingPixels",
    url: "https://rugslayer.com",
  },
  iconUrl: "https://rugslayer.com/icon.svg",
  capabilities: {
    streaming: false,
    pushNotifications: false,
    stateTransitionHistory: false,
  },
  securitySchemes: {
    x402: {
      httpSecurityScheme: {
        scheme: "x402",
        bearerFormat: "USDC micropayment on Solana",
      },
    },
  },
  defaultInputModes: ["application/json"],
  defaultOutputModes: ["application/json"],
  skills: [
    {
      id: "web-scraping",
      name: "Web Scraping",
      description: "Scrape any URL and return cleaned text content. Powered by Playwright headless browser.",
      tags: ["scraping", "web", "playwright", "text-extraction"],
      examples: ["Scrape this webpage for me", "Get the text content from this URL"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "screenshots",
      name: "URL Screenshots",
      description: "Capture full-page screenshots of any URL. Returns base64-encoded PNG.",
      tags: ["screenshot", "web", "playwright", "image"],
      examples: ["Take a screenshot of this website", "Capture this page"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "structured-data",
      name: "Structured Data Extraction",
      description: "Scrape a URL and extract structured JSON data matching a provided schema using AI.",
      tags: ["scraping", "extraction", "ai", "json", "structured-data"],
      examples: ["Extract product prices from this page", "Get all the contact info from this URL"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "code-review",
      name: "Code Review",
      description: "AI-powered security and quality review of submitted code. Finds vulnerabilities, anti-patterns, and suggests improvements.",
      tags: ["code-review", "security", "quality", "ai"],
      examples: ["Review this code for security issues", "Check this function for bugs"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "content-generation",
      name: "Content Generation",
      description: "Generate blog posts, product descriptions, documentation, social posts, and emails.",
      tags: ["content", "generation", "ai", "writing"],
      examples: ["Write a blog post about AI agents", "Generate a product description"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "sentiment-analysis",
      name: "Sentiment Analysis",
      description: "Analyze sentiment of text with entity extraction, key phrases, and confidence scores.",
      tags: ["sentiment", "analysis", "nlp", "ai"],
      examples: ["What's the sentiment of this review?", "Analyze the tone of this text"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "web-search",
      name: "Web Search",
      description: "Search the web via Google and return organic results with titles, links, and snippets.",
      tags: ["search", "google", "web", "serper"],
      examples: ["Search for recent AI agent news", "Find documentation for this library"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
  ],
};

const MCP_CARD = {
  mcp_version: "2025-11-25",
  name: "zero-core-tools",
  display_name: "Zero Core Tools - General-Purpose Agent Tools",
  description:
    "MCP server for AI agents. Web scraping, screenshots, structured data extraction, code review, content generation, and sentiment analysis. Pay per call with USDC via x402.",
  version: "1.0.0",
  vendor: "MeltingPixels",
  homepage: "https://tools.rugslayer.com",
  endpoints: {
    streamable_http: "https://tools.rugslayer.com/mcp",
  },
  pricing: {
    model: "paid",
    free_tools: ["list_tools", "health"],
    paid_tools: {
      scrape_url: "$0.005",
      screenshot_url: "$0.005",
      extract_structured_data: "$0.02",
      review_code: "$0.03",
      generate_content: "$0.05",
      analyze_sentiment: "$0.01",
      search_web: "$0.01",
    },
    payment_methods: ["x402_usdc_solana"],
  },
  rate_limits: {
    x402: "unlimited (pay per call)",
  },
  tools: [
    {
      name: "list_tools",
      description: "List all available tools with pricing and input requirements.",
      price: "FREE",
      input_schema: { type: "object", properties: {} },
    },
    {
      name: "health",
      description: "Server status, uptime, and payment network configuration.",
      price: "FREE",
      input_schema: { type: "object", properties: {} },
    },
    {
      name: "scrape_url",
      description: "Scrape any URL and return cleaned markdown text. Powered by Playwright.",
      price: "$0.005 USDC",
      input_schema: {
        type: "object",
        required: ["url"],
        properties: {
          url: { type: "string", description: "URL to scrape" },
          max_length: { type: "number", description: "Max content length in chars (default: 10000)" },
        },
      },
    },
    {
      name: "screenshot_url",
      description: "Full-page screenshot of any URL. Returns base64-encoded PNG.",
      price: "$0.005 USDC",
      input_schema: {
        type: "object",
        required: ["url"],
        properties: {
          url: { type: "string", description: "URL to screenshot" },
          full_page: { type: "boolean", description: "Capture full page (default: true)" },
          width: { type: "number", description: "Viewport width (default: 1280)" },
          height: { type: "number", description: "Viewport height (default: 720)" },
        },
      },
    },
    {
      name: "extract_structured_data",
      description: "Scrape URL then extract structured JSON via AI per your schema description.",
      price: "$0.02 USDC",
      input_schema: {
        type: "object",
        required: ["url", "schema_description"],
        properties: {
          url: { type: "string", description: "URL to scrape" },
          schema_description: { type: "string", description: "Description of data to extract and desired JSON structure" },
        },
      },
    },
    {
      name: "review_code",
      description: "AI-powered security and quality code review.",
      price: "$0.03 USDC",
      input_schema: {
        type: "object",
        required: ["code"],
        properties: {
          code: { type: "string", description: "Code to review" },
          language: { type: "string", description: "Programming language (auto-detected if omitted)" },
          focus: { type: "string", description: "Focus area: security, quality, performance, or all (default: all)" },
        },
      },
    },
    {
      name: "generate_content",
      description: "Generate blog posts, product descriptions, documentation, social posts, emails.",
      price: "$0.05 USDC",
      input_schema: {
        type: "object",
        required: ["type", "topic"],
        properties: {
          type: { type: "string", description: "Content type: blog_post, product_description, documentation, social_post, email" },
          topic: { type: "string", description: "Topic or subject to write about" },
          tone: { type: "string", description: "Tone: professional, casual, technical, friendly (default: professional)" },
          length: { type: "string", description: "Length: short, medium, long (default: medium)" },
          keywords: { type: "string", description: "Comma-separated keywords to include" },
        },
      },
    },
    {
      name: "analyze_sentiment",
      description: "Sentiment analysis with entity extraction and key phrases.",
      price: "$0.01 USDC",
      input_schema: {
        type: "object",
        required: ["text"],
        properties: {
          text: { type: "string", description: "Text to analyze" },
        },
      },
    },
    {
      name: "search_web",
      description: "Search the web via Google. Returns organic results with titles, links, and snippets.",
      price: "$0.01 USDC",
      input_schema: {
        type: "object",
        required: ["query"],
        properties: {
          query: { type: "string", description: "Search query" },
          num_results: { type: "number", description: "Number of results (default: 10, max: 50)" },
        },
      },
    },
  ],
  install: {
    npm: "npx -y @meltingpixels/zero-core-tools",
    claude_code: "claude mcp add zero-core-tools --transport http https://tools.rugslayer.com/mcp",
    claude_desktop: {
      command: "npx",
      args: ["-y", "@meltingpixels/zero-core-tools"],
      env: {},
    },
  },
  categories: ["web-scraping", "code-review", "content-generation", "analysis", "web-search"],
  tags: ["scraping", "playwright", "ai", "code-review", "content", "sentiment", "search", "x402", "usdc"],
};
