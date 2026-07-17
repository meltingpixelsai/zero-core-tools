// ── Landing pages for Zero Core Tools ──────────────────────────

const SERVER = {
  name: "ZERO CORE TOOLS",
  slug: "zero-core-tools",
  tagline: "General-purpose tools for autonomous agents",
  url: "https://tools.rugslayer.com",
  color: "#00d4ff",
  colorDim: "#00a8cc",
  npm: "@meltingpixels/zero-core-tools",
  github: "https://github.com/meltingpixelsai/harvey-tools",
  tools: [
    { name: "list_tools", desc: "List all tools with pricing", price: "FREE" },
    { name: "health", desc: "Server status and payment config", price: "FREE" },
    { name: "scrape_url", desc: "Scrape any URL, return cleaned text", price: "$0.005" },
    { name: "screenshot_url", desc: "Full-page screenshot as base64 PNG", price: "$0.005" },
    { name: "extract_structured_data", desc: "Scrape URL + AI extract structured JSON", price: "$0.02" },
    { name: "review_code", desc: "Security + quality code review", price: "$0.03" },
    { name: "generate_content", desc: "Generate blog posts, docs, descriptions", price: "$0.05" },
    { name: "analyze_sentiment", desc: "Sentiment analysis + entity extraction", price: "$0.01" },
  ],
};

function baseStyles(color: string): string {
  return `
    *{margin:0;padding:0;box-sizing:border-box}
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
    body{
      background:#0a0a0f;
      color:#c0c0c0;
      font-family:'JetBrains Mono',monospace;
      min-height:100vh;
      overflow-x:hidden;
    }
    .grid-overlay{
      position:fixed;top:0;left:0;width:100%;height:100%;
      background-image:
        linear-gradient(rgba(255,255,255,.02) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,255,255,.02) 1px,transparent 1px);
      background-size:60px 60px;
      animation:gridShift 20s linear infinite;
      pointer-events:none;z-index:0;
    }
    @keyframes gridShift{
      0%{transform:translate(0,0)}
      100%{transform:translate(60px,60px)}
    }
    @keyframes glow{
      0%,100%{text-shadow:0 0 20px ${color}40,0 0 40px ${color}20}
      50%{text-shadow:0 0 30px ${color}60,0 0 60px ${color}30}
    }
    @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
    @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
    .cursor{
      display:inline-block;width:10px;height:1.1em;
      background:${color};vertical-align:text-bottom;
      animation:blink 1s step-end infinite;margin-left:4px;
    }
    a{color:${color};text-decoration:none}
    a:hover{text-decoration:underline}
  `;
}

export function landingHtml(): string {
  const { name, tagline, color, tools } = SERVER;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${name} - MCP Server</title>
  <meta name="description" content="${tagline}. x402-paid MCP server for AI agents."/>
  <style>${baseStyles(color)}
    .container{
      position:relative;z-index:1;
      display:flex;flex-direction:column;align-items:center;justify-content:center;
      min-height:100vh;padding:2rem;
    }
    .server-name{
      font-size:clamp(2rem,6vw,4rem);font-weight:700;
      color:${color};letter-spacing:0.15em;
      animation:glow 3s ease-in-out infinite;
      margin-bottom:0.5rem;
    }
    .tagline{
      font-size:clamp(0.85rem,2vw,1.1rem);
      color:#888;margin-bottom:2.5rem;
    }
    .terminal{
      background:#0d0d14;border:1px solid #1a1a2e;
      border-radius:8px;padding:1.5rem 2rem;
      max-width:520px;width:100%;
      animation:fadeIn 0.6s ease-out;
    }
    .terminal-line{
      display:flex;gap:1rem;margin:0.35rem 0;
      font-size:0.85rem;line-height:1.6;
    }
    .terminal-label{color:#555}
    .terminal-value{color:#e0e0e0}
    .terminal-value.ok{color:${color}}
    .mcp-note{
      margin-top:2rem;font-size:0.8rem;
      color:#555;text-align:center;
    }
    .dev-link{
      margin-top:1.5rem;font-size:0.8rem;
      color:#444;
    }
    .dev-link a{color:#666}
    .dev-link a:hover{color:${color}}
    .footer{
      margin-top:2rem;font-size:0.7rem;color:#333;
    }
  </style>
</head>
<body>
  <div class="grid-overlay"></div>
  <div class="container">
    <div class="server-name">${name}</div>
    <div class="tagline">${tagline}<span class="cursor"></span></div>
    <div class="terminal">
      <div class="terminal-line"><span class="terminal-label">server</span><span class="terminal-value">${SERVER.slug}</span></div>
      <div class="terminal-line"><span class="terminal-label">version</span><span class="terminal-value">1.0.0</span></div>
      <div class="terminal-line"><span class="terminal-label">protocol</span><span class="terminal-value">MCP + x402</span></div>
      <div class="terminal-line"><span class="terminal-label">payment</span><span class="terminal-value">USDC on Solana</span></div>
      <div class="terminal-line"><span class="terminal-label">tools</span><span class="terminal-value">${tools.length} available</span></div>
      <div class="terminal-line"><span class="terminal-label">status</span><span class="terminal-value ok">ONLINE</span></div>
    </div>
    <div class="mcp-note">This endpoint serves AI agents via the Model Context Protocol.</div>
    <div class="dev-link"><a href="/dev">Are you a developer? View tools & connect &rarr;</a></div>
    <div class="footer">Built by <a href="https://meltingpixels.com" style="color:#444">MeltingPixels</a></div>
  </div>
</body>
</html>`;
}

export function devHtml(): string {
  const { name, slug, tagline, color, colorDim, url, npm, github, tools } = SERVER;
  const toolRows = tools
    .map(
      (t) =>
        `<tr><td class="tool-name">${t.name}</td><td class="tool-desc">${t.desc}</td><td class="tool-price${t.price === "FREE" ? " free" : ""}">${t.price === "FREE" ? "FREE" : t.price + " USDC"}</td></tr>`
    )
    .join("\n        ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${name} - Developer Docs</title>
  <meta name="description" content="${tagline}. Tool reference and MCP connect instructions."/>
  <style>${baseStyles(color)}
    .container{
      position:relative;z-index:1;
      max-width:700px;margin:0 auto;padding:3rem 1.5rem;
    }
    .back{font-size:0.8rem;margin-bottom:2rem;display:inline-block;color:#555}
    .back:hover{color:${color}}
    h1{color:${color};font-size:1.6rem;margin-bottom:0.3rem}
    .subtitle{color:#888;font-size:0.9rem;margin-bottom:2rem}
    h2{color:#e0e0e0;font-size:1rem;margin:2rem 0 0.8rem;border-bottom:1px solid #1a1a2e;padding-bottom:0.4rem}
    table{width:100%;border-collapse:collapse;font-size:0.8rem}
    th{text-align:left;color:#555;padding:0.4rem 0.6rem;border-bottom:1px solid #1a1a2e;font-weight:400}
    td{padding:0.4rem 0.6rem;border-bottom:1px solid #111}
    .tool-name{color:${color};white-space:nowrap}
    .tool-desc{color:#999}
    .tool-price{color:#e0e0e0;white-space:nowrap;text-align:right}
    .tool-price.free{color:${colorDim}}
    .code-block{
      background:#0d0d14;border:1px solid #1a1a2e;border-radius:6px;
      padding:1rem 1.2rem;font-size:0.8rem;color:#e0e0e0;
      overflow-x:auto;margin:0.5rem 0;white-space:pre;
    }
    .links{display:flex;flex-wrap:wrap;gap:1rem;margin-top:0.5rem;font-size:0.8rem}
    .footer{margin-top:3rem;font-size:0.7rem;color:#333;text-align:center}
  </style>
</head>
<body>
  <div class="grid-overlay"></div>
  <div class="container">
    <a class="back" href="/">&larr; Back</a>
    <h1>${name}</h1>
    <div class="subtitle">${tagline}</div>

    <h2>Tools</h2>
    <table>
      <tr><th>Tool</th><th>Description</th><th style="text-align:right">Price</th></tr>
      ${toolRows}
    </table>

    <h2>Connect via MCP</h2>
    <div class="code-block">claude mcp add ${slug} --transport http ${url}</div>

    <h2>Install via npm</h2>
    <div class="code-block">npm install ${npm}</div>

    <h2>Links</h2>
    <div class="links">
      <a href="${github}">GitHub</a>
      <a href="https://www.npmjs.com/package/${npm}">npm</a>
      <a href="/llms.txt">llms.txt</a>
      <a href="/health">Health</a>
      <a href="/pricing">Pricing (JSON)</a>
      <a href="/.well-known/mcp.json">mcp.json</a>
    </div>

    <div class="footer">Built by <a href="https://meltingpixels.com" style="color:#444">MeltingPixels</a></div>
  </div>
</body>
</html>`;
}
