import { test } from "node:test";
import assert from "node:assert/strict";
import {
  declaredBodyTooLarge,
  jsonElementCount,
  jsonTextDepth,
  MCP_ALLOWED_METHODS,
  MCP_MAX_BATCH,
  MCP_MAX_BODY_BYTES,
  MCP_MAX_ELEMENTS,
  MCP_MAX_JSON_DEPTH,
  MCP_NOT_UTF8,
  MCP_TOO_LARGE,
  mcpPreReadProblem,
  mcpRequestProblem,
  readCappedText,
  unsupportedCharset,
} from "./request-guard.js";

// The depth, batch and method cases are RelayZero's (src/api/mcp/request-guard.test.ts).

const nested = (depth: number) => "[".repeat(depth) + "]".repeat(depth);
const call = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "some_tool", arguments: { context: { a: { b: [1, 2, { c: "d" }] } } }, _meta: { "x402/payment": "tok" } },
});
const cancel = JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1, reason: "x" } });

test("mcpRequestProblem passes ordinary MCP requests on", () => {
  assert.equal(mcpRequestProblem("POST", call), null);
  assert.equal(mcpRequestProblem("POST", `[${call},${call}]`), null);
  assert.equal(mcpRequestProblem("POST", JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })), null);
  assert.equal(mcpRequestProblem("GET", null), null);
  assert.equal(mcpRequestProblem("DELETE", null), null);
});

test("mcpRequestProblem answers a body that is not JSON with a parse error", () => {
  assert.deepEqual(mcpRequestProblem("POST", "{"), { status: 400, code: -32700, message: "Parse error" });
  assert.equal(mcpRequestProblem("POST", "")?.code, -32700);
  assert.equal(mcpRequestProblem("POST", null)?.code, -32700);
});

test("mcpRequestProblem refuses JSON nested deep enough to overflow the stack when re-serialized", () => {
  const deep = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":${nested(100000)}}}`;
  assert.throws(() => JSON.stringify(JSON.parse(deep)), RangeError);
  assert.deepEqual(mcpRequestProblem("POST", deep), { status: 400, code: -32600, message: "Invalid Request: nested too deeply" });
  // A message nested to exactly the limit passes; one level more is refused for its depth (message + params = 2 levels).
  const atDepth = (d: number) => `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":${nested(d - 2)}}}`;
  assert.equal(jsonTextDepth(atDepth(MCP_MAX_JSON_DEPTH)), MCP_MAX_JSON_DEPTH);
  assert.equal(mcpRequestProblem("POST", atDepth(MCP_MAX_JSON_DEPTH)), null);
  assert.deepEqual(mcpRequestProblem("POST", atDepth(MCP_MAX_JSON_DEPTH + 1)), { status: 400, code: -32600, message: "Invalid Request: nested too deeply" });
  assert.equal(mcpRequestProblem("POST", nested(MCP_MAX_JSON_DEPTH + 1))?.status, 400);
});

test("mcpRequestProblem checks the depth before parsing, so a deep body is never built", () => {
  // Not valid JSON at all (never closed): the depth scan refuses it before JSON.parse would run.
  assert.deepEqual(mcpRequestProblem("POST", "[".repeat(100000)), { status: 400, code: -32600, message: "Invalid Request: nested too deeply" });
});

test("mcpRequestProblem caps JSON-RPC batches", () => {
  const batch = (n: number) => `[${Array.from({ length: n }, () => call).join(",")}]`;
  assert.equal(mcpRequestProblem("POST", batch(MCP_MAX_BATCH)), null);
  assert.deepEqual(mcpRequestProblem("POST", batch(MCP_MAX_BATCH + 1)), {
    status: 400,
    code: -32600,
    message: `Invalid Request: at most ${MCP_MAX_BATCH} messages per batch`,
  });
});

test("mcpRequestProblem answers methods mcp-handler never responds to", () => {
  for (const method of ["PUT", "PATCH", "HEAD", "OPTIONS"]) {
    assert.equal(mcpRequestProblem(method, null)?.status, 405, method);
  }
  assert.equal(MCP_ALLOWED_METHODS, "GET, POST, DELETE");
});

test("a cancellation is accepted and ignored, so no client can cancel another client's call", () => {
  assert.deepEqual(mcpRequestProblem("POST", cancel), { status: 202, code: 0, message: "notifications/cancelled is ignored" });
  assert.equal(mcpRequestProblem("POST", `[${call},${cancel}]`)?.status, 400);
});

test("jsonTextDepth counts bracket nesting and ignores brackets inside strings", () => {
  assert.equal(jsonTextDepth('"x"'), 0);
  assert.equal(jsonTextDepth("{}"), 1);
  assert.equal(jsonTextDepth('{"a":[1,{"b":2}]}'), 3);
  assert.equal(jsonTextDepth('{"a":"[[[{{{"}'), 1);
  assert.equal(jsonTextDepth('{"a":"\\"[[[","b":[]}'), 2);
  assert.equal(jsonTextDepth(nested(100000)), 100000);
});

test("jsonTextDepth stays flat on a wide body", () => {
  assert.equal(jsonTextDepth(`[${"1,".repeat(1_000_000)}1]`), 1);
});

// Size and element limits (GHSA-f897-62hf-6gxq, GHSA-46jr-4wx8-v453).
const callWith = (args: unknown) =>
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "some_tool", arguments: args } });

test("mcpRequestProblem refuses a body over MCP_MAX_BODY_BYTES with 413, counting UTF-8 bytes", () => {
  const room = MCP_MAX_BODY_BYTES - Buffer.byteLength(callWith({ text: "" }));
  const fill = (n: number, ch: string) => callWith({ text: ch.repeat(n) });
  const atCap = fill(room, "x");
  assert.equal(Buffer.byteLength(atCap), MCP_MAX_BODY_BYTES);
  assert.equal(mcpRequestProblem("POST", atCap), null);
  assert.deepEqual(mcpRequestProblem("POST", fill(room + 1, "x")), MCP_TOO_LARGE);
  // "é" is one UTF-16 unit but two UTF-8 bytes: the cap is in bytes, not string length.
  const half = Math.floor(room / 2);
  assert.equal(mcpRequestProblem("POST", fill(half, "é")), null);
  const over = fill(half + 1, "é");
  assert.ok(over.length < MCP_MAX_BODY_BYTES && Buffer.byteLength(over) > MCP_MAX_BODY_BYTES);
  assert.deepEqual(mcpRequestProblem("POST", over), MCP_TOO_LARGE);
  assert.equal(MCP_TOO_LARGE.status, 413);
});

test("mcpRequestProblem refuses a body holding more than MCP_MAX_ELEMENTS array elements and object keys", () => {
  const tooMany = { status: 400, code: -32600, message: `Invalid Request: more than ${MCP_MAX_ELEMENTS} array elements and object keys` };
  // The envelope holds 7: jsonrpc, id, method, params; name, arguments; items.
  const withItems = (n: number) => callWith({ items: Array.from({ length: n }, () => 0) });
  assert.equal(jsonElementCount(JSON.parse(withItems(MCP_MAX_ELEMENTS - 7)), MCP_MAX_ELEMENTS), MCP_MAX_ELEMENTS);
  assert.equal(mcpRequestProblem("POST", withItems(MCP_MAX_ELEMENTS - 7)), null);
  assert.deepEqual(mcpRequestProblem("POST", withItems(MCP_MAX_ELEMENTS - 6)), tooMany);
  // Object keys count like array elements (envelope 6: jsonrpc, id, method, params; name, arguments).
  const withKeys = (n: number) => callWith(Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i])));
  assert.equal(mcpRequestProblem("POST", withKeys(MCP_MAX_ELEMENTS - 6)), null);
  assert.deepEqual(mcpRequestProblem("POST", withKeys(MCP_MAX_ELEMENTS - 5)), tooMany);
  // Messages in a batch count together: 10 x 107 + 10 = 1,080, while each message alone holds 107.
  const part = withItems(100);
  assert.deepEqual(mcpRequestProblem("POST", `[${Array.from({ length: MCP_MAX_BATCH }, () => part).join(",")}]`), tooMany);
  assert.equal(mcpRequestProblem("POST", `[${part},${part}]`), null);
  // The largest real input here is plain strings: far below the limit, whatever its length.
  const verifyCall = callWith({ request_description: "r", response_data: "y".repeat(100_000), expected_schema: "{}", sla_requirements: "s", service_id: "x" });
  assert.ok(jsonElementCount(JSON.parse(verifyCall), MCP_MAX_ELEMENTS) < 20);
  assert.equal(mcpRequestProblem("POST", verifyCall), null);
});

test("jsonElementCount counts array elements and object keys, and stops once past the limit", () => {
  assert.equal(jsonElementCount("x", 10), 0);
  assert.equal(jsonElementCount(null, 10), 0);
  assert.equal(jsonElementCount([], 10), 0);
  assert.equal(jsonElementCount({ a: 1, b: [1, 2, { c: 3 }] }, 100), 6);
  // The outer array alone passes the limit, so its million children are never visited.
  const wide = Array.from({ length: 1_000_000 }, () => [1, 2, 3]);
  assert.equal(jsonElementCount(wide, 10), 1_000_000);
});

test("declaredBodyTooLarge refuses a Content-Length over the cap and ignores one it cannot read", () => {
  assert.equal(declaredBodyTooLarge(undefined), false);
  assert.equal(declaredBodyTooLarge(String(MCP_MAX_BODY_BYTES)), false);
  assert.equal(declaredBodyTooLarge(String(MCP_MAX_BODY_BYTES + 1)), true);
  assert.equal(declaredBodyTooLarge(" 2000000 "), true);
  // Node accepts long digit runs and leading zeros: a long run is too large, leading zeros don't count.
  assert.equal(declaredBodyTooLarge("99999999999999999"), true);
  assert.equal(declaredBodyTooLarge("00000000000000002000000"), true);
  assert.equal(declaredBodyTooLarge("0000000000000000000001"), false);
  // Not all digits: Node answers 400 before the app sees them.
  for (const v of ["", "abc", "-5", "1e9", "12.5"]) assert.equal(declaredBodyTooLarge(v), false, v);
});

test("a top-level JSON string, number or empty batch is refused: mcp-handler would unwrap a string into a message", () => {
  const shape = { status: 400, code: -32600, message: "Invalid Request: the body must be a JSON-RPC message or a batch of messages" };
  // The reviewed bypass: a batch over every limit, wrapped as a JSON string. mcp-handler 1.0.2 pushes the string's
  // contents to the SDK, which parses them as the real batch.
  const heavy = JSON.stringify(Array.from({ length: 50 }, () => JSON.parse(callWith({ items: Array.from({ length: 2_000 }, () => 0) }))));
  assert.equal(mcpRequestProblem("POST", heavy)?.status, 400);
  assert.deepEqual(mcpRequestProblem("POST", JSON.stringify(heavy)), shape);
  for (const body of ['"x"', "1", "true", "null", "[]", "[1]", '["x"]', `[${call},"x"]`, `[${call},[]]`, "[[]]"]) {
    assert.deepEqual(mcpRequestProblem("POST", body), shape, body);
  }
});

test("unsupportedCharset accepts UTF-8 or no charset and refuses any other", () => {
  for (const ct of [undefined, "application/json", "application/json; charset=utf-8", "application/json;charset=UTF-8", 'application/json; charset="utf8"', "text/plain"]) {
    assert.equal(unsupportedCharset(ct), false, String(ct));
  }
  for (const ct of ["application/json; charset=utf-7", "application/json; charset=iso-8859-1", "application/json; boundary=x; charset=UTF-16LE"]) {
    assert.equal(unsupportedCharset(ct), true, ct);
  }
});

test("mcpPreReadProblem answers an oversize Content-Length with 413 and a non-UTF-8 charset with 415", () => {
  assert.equal(mcpPreReadProblem(undefined, "application/json"), null);
  assert.equal(mcpPreReadProblem("120", "application/json; charset=utf-8"), null);
  assert.deepEqual(mcpPreReadProblem(String(MCP_MAX_BODY_BYTES + 1), "application/json"), MCP_TOO_LARGE);
  assert.deepEqual(mcpPreReadProblem("120", "application/json; charset=utf-7"), MCP_NOT_UTF8);
  assert.equal(MCP_NOT_UTF8.status, 415);
});

test("readCappedText reads up to the cap and stops at the first byte past it", async () => {
  const stream = (sizes: number[], ch = 0x61) => {
    let pulls = 0;
    const s = new ReadableStream<Uint8Array>({
      pull(controller) {
        const n = sizes[pulls++];
        if (n === undefined) controller.close();
        else controller.enqueue(new Uint8Array(n).fill(ch));
      },
    });
    return { s, pulls: () => pulls };
  };
  assert.equal(await readCappedText(null, 10), "");
  assert.equal(await readCappedText(stream([4, 6]).s, 10), "aaaaaaaaaa");
  const over = stream([6, 5, 1000, 1000]);
  assert.equal(await readCappedText(over.s, 10), null);
  assert.ok(over.pulls() <= 3, `read ${over.pulls()} chunks after passing the cap`);
  // UTF-8 is decoded once, here: "é" arrives as two bytes split across chunks.
  const e = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(Uint8Array.of(0x22, 0xc3));
      controller.enqueue(Uint8Array.of(0xa9, 0x22));
      controller.close();
    },
  });
  assert.equal(await readCappedText(e, 10), '"é"');
});
