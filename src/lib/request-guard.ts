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
 *
 * Size and element limits (GHSA-f897-62hf-6gxq, GHSA-46jr-4wx8-v453): the MCP
 * SDK this server runs (the 1.18.2 copy mcpay pins) limits neither the body
 * size nor how many array elements and object keys it validates in one
 * request, and one request can exhaust the heap. SDK 1.32 cannot run under
 * mcpay's mcp-handler 1.0.2 (its fake request has no rawHeaders, so the SDK
 * sees no headers), so the limits live here:
 * - the body is read through a counting reader that stops past 1 MiB (413), and
 *   a declared Content-Length over 1 MiB is refused before reading;
 * - a charset other than UTF-8 is refused (415): the SDK decodes with the
 *   declared charset, so a UTF-7 body could read as one string here and as
 *   extra arrays and keys there;
 * - the body must be a JSON-RPC message (an object) or a batch of them: mcp-
 *   handler unwraps a top-level JSON string and the SDK parses its contents as
 *   the real message, which would carry anything past these checks;
 * - a body holding more than 1,000 array elements and object keys in total
 *   gets 400. Every tool here takes plain strings, so a real call holds fewer
 *   than 20.
 * index.ts then hands mcp-handler a new Request built from exactly the text
 * checked here, so both parse the same message.
 */

/** Far deeper than any MCP message; tool arguments that need more are refused. */
export const MCP_MAX_JSON_DEPTH = 64;
/** Messages allowed in one JSON-RPC batch. */
export const MCP_MAX_BATCH = 10;
/** Largest POST body, in bytes. */
export const MCP_MAX_BODY_BYTES = 1_048_576;
/** Array elements plus object keys allowed in one POST body, all messages together. */
export const MCP_MAX_ELEMENTS = 1_000;
/** The methods mcp-handler answers (the Allow header of a 405). */
export const MCP_ALLOWED_METHODS = "GET, POST, DELETE";

export interface McpRequestProblem {
  /** 202: a notification accepted and ignored (answer with no body); 400, 405, 413 and 415: a JSON-RPC error. */
  status: 202 | 400 | 405 | 413 | 415;
  code: number;
  message: string;
}

/** The answer to a body over MCP_MAX_BODY_BYTES. */
export const MCP_TOO_LARGE: McpRequestProblem = {
  status: 413,
  code: -32600,
  message: `Invalid Request: the body is over ${MCP_MAX_BODY_BYTES} bytes`,
};

/** The answer to a body declared in a charset other than UTF-8. */
export const MCP_NOT_UTF8: McpRequestProblem = {
  status: 415,
  code: -32600,
  message: "Unsupported Media Type: the body must be UTF-8 JSON",
};

/**
 * True when a Content-Length header declares more than MCP_MAX_BODY_BYTES. Leading zeros are ignored, and any
 * longer run of digits counts as too large (Node accepts them). A value that is not all digits is left to Node, which
 * already answers 400 for it.
 */
export function declaredBodyTooLarge(contentLength: string | undefined): boolean {
  if (contentLength === undefined) return false;
  const v = contentLength.trim();
  if (!/^\d+$/.test(v)) return false;
  const digits = v.replace(/^0+(?=\d)/, "");
  return digits.length > 16 || Number(digits) > MCP_MAX_BODY_BYTES;
}

/** True when a Content-Type header names a charset other than UTF-8 (absent is fine: JSON is UTF-8). */
export function unsupportedCharset(contentType: string | undefined): boolean {
  if (contentType === undefined) return false;
  for (const param of contentType.split(";").slice(1)) {
    const eq = param.indexOf("=");
    if (eq < 0) continue;
    if (param.slice(0, eq).trim().toLowerCase() !== "charset") continue;
    const value = param.slice(eq + 1).trim().replace(/^"(.*)"$/, "$1").toLowerCase();
    if (value !== "utf-8" && value !== "utf8") return true;
  }
  return false;
}

/** What to answer from the headers alone, before the body is read, or null. */
export function mcpPreReadProblem(contentLength: string | undefined, contentType: string | undefined): McpRequestProblem | null {
  if (declaredBodyTooLarge(contentLength)) return MCP_TOO_LARGE;
  if (unsupportedCharset(contentType)) return MCP_NOT_UTF8;
  return null;
}

/**
 * Reads a body as UTF-8 text, or returns null as soon as it passes `max` bytes (the rest is never read or kept).
 * A missing body reads as "".
 */
export async function readCappedText(body: ReadableStream<Uint8Array> | null, max: number): Promise<string | null> {
  if (body === null) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return new TextDecoder("utf-8").decode(Buffer.concat(chunks));
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

/**
 * Array elements plus object keys in a parsed JSON value. Counting stops once it passes `limit`, and a container's
 * children are queued only after its own count is added, so the work stays bounded by the limit.
 */
export function jsonElementCount(value: unknown, limit: number): number {
  let count = 0;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (Array.isArray(v)) {
      count += v.length;
      if (count > limit) return count;
      for (const x of v) if (typeof x === "object" && x !== null) stack.push(x);
    } else if (typeof v === "object" && v !== null) {
      const keys = Object.keys(v);
      count += keys.length;
      if (count > limit) return count;
      for (const k of keys) {
        const x = (v as Record<string, unknown>)[k];
        if (typeof x === "object" && x !== null) stack.push(x);
      }
    }
  }
  return count;
}

const isMessage = (m: unknown): boolean => typeof m === "object" && m !== null && !Array.isArray(m);

const isCancellation = (message: unknown): boolean =>
  typeof message === "object" && message !== null && (message as { method?: unknown }).method === "notifications/cancelled";

/** What to answer instead of passing the request on, or null to pass it on. */
export function mcpRequestProblem(method: string, body: string | null): McpRequestProblem | null {
  if (method !== "GET" && method !== "POST" && method !== "DELETE") {
    return { status: 405, code: -32000, message: "Method not allowed." };
  }
  if (method !== "POST") return null;
  const text = body ?? "";
  // A UTF-16 length over the cap is always over it in UTF-8 too, so the exact byte count runs only near the cap.
  if (text.length > MCP_MAX_BODY_BYTES || (text.length * 3 > MCP_MAX_BODY_BYTES && Buffer.byteLength(text, "utf8") > MCP_MAX_BODY_BYTES)) {
    return MCP_TOO_LARGE;
  }
  if (jsonTextDepth(text) > MCP_MAX_JSON_DEPTH) {
    return { status: 400, code: -32600, message: "Invalid Request: nested too deeply" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: 400, code: -32700, message: "Parse error" };
  }
  if (Array.isArray(parsed) ? parsed.length === 0 || !parsed.every(isMessage) : !isMessage(parsed)) {
    return { status: 400, code: -32600, message: "Invalid Request: the body must be a JSON-RPC message or a batch of messages" };
  }
  if (jsonElementCount(parsed, MCP_MAX_ELEMENTS) > MCP_MAX_ELEMENTS) {
    return { status: 400, code: -32600, message: `Invalid Request: more than ${MCP_MAX_ELEMENTS} array elements and object keys` };
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
