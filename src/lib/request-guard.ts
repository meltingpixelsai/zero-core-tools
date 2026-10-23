/**
 * Checks a request before mcp-handler sees it.
 *
 * mcp-handler handles each request in a promise nobody awaits. It throws on a
 * body that is not JSON, and on JSON nested deep enough that re-serializing it
 * overflows the stack; the unhandledRejection handler in index.ts keeps the
 * process up, but that request never gets an answer. A method mcp-handler does
 * not handle (PUT, PATCH, HEAD, ...) never gets an answer either.
 *
 * A JSON-RPC batch runs every call it holds, and each paid call does some
 * work before payment (reading the payment token, prechecks), so batches are
 * capped too. MCP clients send one message per request; the current MCP
 * revision dropped batching.
 *
 * mcp-handler also serves every client through one shared transport that knows
 * a request only by its JSON-RPC id, and every client numbers its requests from
 * the start. A "notifications/cancelled" for id 1 from anyone would drop the
 * answer to whichever client's call holds id 1, after its payment settled. A
 * cancellation is therefore accepted and ignored: the call runs to the end and
 * answers its own client.
 *
 * Depth, batch and method rules as in RelayZero's src/api/mcp/request-guard.ts.
 * Here the depth scan runs before parsing, so a deep body is refused before it
 * is built in memory.
 */

/** Far deeper than any MCP message; tool arguments that need more are refused. */
export const MCP_MAX_JSON_DEPTH = 64;
/** Messages allowed in one JSON-RPC batch. */
export const MCP_MAX_BATCH = 10;
/** The methods mcp-handler answers (the Allow header of a 405). */
export const MCP_ALLOWED_METHODS = "GET, POST, DELETE";

export interface McpRequestProblem {
  /** 202: a notification accepted and ignored (answer with no body); 400 and 405: a JSON-RPC error. */
  status: 202 | 400 | 405;
  code: number;
  message: string;
}

/** Deepest bracket nesting in JSON text, skipping string contents: one pass, no allocation. */
export function jsonTextDepth(text: string): number {
  let depth = 0;
  let max = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++; // backslash: skip the escaped character
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x7b || c === 0x5b) {
      if (++depth > max) max = depth;
    } else if (c === 0x7d || c === 0x5d) {
      depth--;
    }
  }
  return max;
}

const isCancellation = (message: unknown): boolean =>
  typeof message === "object" && message !== null && (message as { method?: unknown }).method === "notifications/cancelled";

/** What to answer instead of passing the request on, or null to pass it on. */
export function mcpRequestProblem(method: string, body: string | null): McpRequestProblem | null {
  if (method !== "GET" && method !== "POST" && method !== "DELETE") {
    return { status: 405, code: -32000, message: "Method not allowed." };
  }
  if (method !== "POST") return null;
  const text = body ?? "";
  if (jsonTextDepth(text) > MCP_MAX_JSON_DEPTH) {
    return { status: 400, code: -32600, message: "Invalid Request: nested too deeply" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: 400, code: -32700, message: "Parse error" };
  }
  if (Array.isArray(parsed)) {
    if (parsed.length > MCP_MAX_BATCH) {
      return { status: 400, code: -32600, message: `Invalid Request: at most ${MCP_MAX_BATCH} messages per batch` };
    }
    if (parsed.some(isCancellation)) {
      return { status: 400, code: -32600, message: "Invalid Request: notifications/cancelled is not accepted in a batch" };
    }
    return null;
  }
  if (isCancellation(parsed)) {
    return { status: 202, code: 0, message: "notifications/cancelled is ignored" };
  }
  return null;
}
