import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonTextDepth, MCP_MAX_BATCH, MCP_MAX_JSON_DEPTH, mcpRequestProblem } from "./request-guard.js";

// Same cases as RelayZero's src/api/mcp/request-guard.test.ts.

const nested = (depth: number) => "[".repeat(depth) + "]".repeat(depth);
const call = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "some_tool", arguments: { context: { a: { b: [1, 2, { c: "d" }] } } }, _meta: { "x402/payment": "tok" } },
});

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
  assert.equal(mcpRequestProblem("POST", nested(MCP_MAX_JSON_DEPTH)), null);
  assert.equal(mcpRequestProblem("POST", nested(MCP_MAX_JSON_DEPTH + 1))?.status, 400);
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
