import { after, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { encodePayment } from "x402/schemes";
import type { SettleResponse, VerifyResponse } from "x402/types";
import {
  createSettleFirstPaidTools,
  paymentClaimKey,
  type FacilitatorClient,
  type SettleFirstConfig,
  type ToolResult,
  type X402Settlement,
} from "./x402-settle-first.js";

type Handler = (args: unknown, extra: unknown) => Promise<ToolResult>;

const CONFIG: SettleFirstConfig = {
  facilitator: { url: "https://facilitator.example" },
  recipient: { svm: { address: "Recipient11111111111111111111111111111111111", isTestnet: false } },
};

const tempDirs: string[] = [];
function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "x402-claims-"));
  tempDirs.push(dir);
  return dir;
}
after(() => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

/** A Solana wire transaction: 2 signature slots (fee payer, payer), then the message. */
function txBase64(message: string, slotFill = 0): string {
  return Buffer.concat([Buffer.from([2]), Buffer.alloc(128, slotFill), Buffer.from(message)]).toString("base64");
}

function token(message: string, slotFill = 0): string {
  return encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: txBase64(message, slotFill) } });
}

function paid(tok: string): { _meta: Record<string, unknown> } {
  return { _meta: { "x402/payment": tok } };
}

interface Harness {
  handler: Handler;
  events: string[];
  logs: string[];
  extras: unknown[];
  claimsDir: string;
}

function harness(opts: {
  verify?: () => Promise<VerifyResponse>;
  settle?: () => Promise<SettleResponse>;
  claimsDir?: string;
  toolResult?: () => Promise<ToolResult>;
  precheck?: (args: { x?: string }) => string | null;
  events?: string[];
} = {}): Harness {
  const events: string[] = opts.events ?? [];
  const logs: string[] = [];
  const extras: unknown[] = [];
  const claimsDir = opts.claimsDir ?? tempDir();
  const facilitator: FacilitatorClient = {
    supported: async () => {
      events.push("supported");
      return { kinds: [{ scheme: "exact", network: "solana", extra: { feePayer: "FeePayer111111111111111111111111111111111111" } }] };
    },
    verify: async () => {
      events.push("verify");
      return opts.verify ? opts.verify() : { isValid: true, payer: "Payer1111" };
    },
    settle: async () => {
      events.push("settle");
      return opts.settle ? opts.settle() : { success: true, transaction: "sig-1", network: "solana", payer: "Payer1111" };
    },
  };
  const settleFirst = createSettleFirstPaidTools(CONFIG, {
    facilitator,
    claimsDir,
    log: (line) => logs.push(line),
    info: (line) => logs.push(line),
  });
  const tools = new Map<string, Handler>();
  const server = {
    tool: (...args: unknown[]) => {
      tools.set(args[0] as string, args[4] as Handler);
    },
  };
  settleFirst(server)(
    "echo",
    "Echo",
    "$0.01",
    {},
    {},
    async (_args: { x?: string }, extra: unknown) => {
      events.push("tool");
      extras.push(extra);
      return opts.toolResult ? opts.toolResult() : { content: [{ type: "text", text: "ok" }] };
    },
    { precheck: opts.precheck },
  );
  const handler = tools.get("echo");
  assert.ok(handler, "tool registered");
  return { handler, events, logs, extras, claimsDir };
}

function errorCode(result: ToolResult): unknown {
  return (result._meta?.["x402/error"] as { error?: unknown } | undefined)?.error;
}

const paymentEvents = (events: string[]) => events.filter((e) => e !== "supported");

test("no payment token: payment required, nothing runs", async () => {
  const h = harness();
  const result = await h.handler({}, {});
  assert.equal(result.isError, true);
  assert.equal(errorCode(result), "PAYMENT_REQUIRED");
  const accepts = (result._meta?.["x402/error"] as { accepts: Array<{ network: string; payTo: string }> }).accepts;
  assert.equal(accepts.length, 1);
  assert.equal(accepts[0].network, "solana");
  assert.equal(accepts[0].payTo, CONFIG.recipient.svm.address);
  assert.deepEqual(paymentEvents(h.events), []);
});

test("the payment settles before the tool runs, and the tool sees the settlement", async () => {
  const h = harness();
  const result = await h.handler({}, paid(token("pay-1")));
  assert.equal(result.isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle", "tool"]);
  const response = result._meta?.["x402/payment-response"] as X402Settlement & { success: boolean };
  assert.equal(response.success, true);
  assert.equal(response.transaction, "sig-1");
  const settlement = (h.extras[0] as { x402Settlement: X402Settlement }).x402Settlement;
  assert.equal(settlement.payer, "Payer1111");
});

test("a payment that does not settle never runs the tool, is logged, and can be retried", async () => {
  let attempt = 0;
  const h = harness({
    settle: async () =>
      ++attempt === 1
        ? { success: false, errorReason: "settle_exact_svm_transaction_confirmation_timed_out", transaction: "sig-maybe", network: "solana" }
        : { success: true, transaction: "sig-2", network: "solana", payer: "Payer1111" },
  });
  const tok = token("pay-2");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), "settle_exact_svm_transaction_confirmation_timed_out");
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle"]);
  assert.ok(h.logs.some((l) => l.includes("settle failed") && l.includes("confirmation_timed_out") && l.includes("sig-maybe")));
  const second = await h.handler({}, paid(tok));
  assert.equal(second.isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle", "verify", "settle", "tool"]);
});

test("a settle request that throws does not run the tool and releases the claim", async () => {
  let attempt = 0;
  const h = harness({
    settle: async () => {
      if (++attempt === 1) throw new Error("Failed to settle payment: 502 Bad Gateway");
      return { success: true, transaction: "sig-3", network: "solana", payer: "Payer1111" };
    },
  });
  const tok = token("pay-3");
  assert.equal(errorCode(await h.handler({}, paid(tok))), "SETTLEMENT_FAILED");
  assert.equal(h.events.includes("tool"), false);
  assert.ok(h.logs.some((l) => l.includes("settle request failed")));
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("an invalid payment is refused before settle, and the fee-payer cache is refreshed", async () => {
  const h = harness({ verify: async () => ({ isValid: false, invalidReason: "invalid_exact_svm_payload_transaction" }) });
  const result = await h.handler({}, paid(token("pay-4")));
  assert.equal(errorCode(result), "invalid_exact_svm_payload_transaction");
  assert.deepEqual(paymentEvents(h.events), ["verify"]);
  await h.handler({}, paid(token("pay-4b")));
  assert.equal(h.events.filter((e) => e === "supported").length, 2, "supported() asked again after a failed verify");
  await h.handler({}, paid(token("pay-4c")));
  assert.equal(h.events.filter((e) => e === "supported").length, 2, "no second refresh within 30 seconds");
  assert.ok(h.logs.some((l) => l.includes("payment claims in")), "claim directory logged at startup");
});

test("one payment sent five times in parallel runs the tool once", async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const h = harness({
    settle: async () => {
      await gate;
      return { success: true, transaction: "sig-5", network: "solana", payer: "Payer1111" };
    },
  });
  const tok = token("pay-5");
  const pending = Array.from({ length: 5 }, () => h.handler({}, paid(tok)));
  await new Promise((resolve) => setImmediate(resolve));
  release();
  const results = await Promise.all(pending);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  assert.equal(h.events.filter((e) => e === "settle").length, 1);
  assert.equal(results.filter((r) => errorCode(r) === "PAYMENT_ALREADY_USED").length, 4);
});

test("one payment sent to two servers sharing the claim directory runs one tool", async () => {
  const claimsDir = tempDir();
  const events: string[] = [];
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const settle = async (): Promise<SettleResponse> => {
    await gate;
    return { success: true, transaction: "sig-6", network: "solana", payer: "Payer1111" };
  };
  const serverA = harness({ claimsDir, events, settle });
  const serverB = harness({ claimsDir, events, settle });
  const tok = token("pay-6");
  const pending = [serverA.handler({}, paid(tok)), serverB.handler({}, paid(tok))];
  await new Promise((resolve) => setImmediate(resolve));
  release();
  const results = await Promise.all(pending);
  assert.equal(events.filter((e) => e === "tool").length, 1);
  assert.equal(results.filter((r) => errorCode(r) === "PAYMENT_ALREADY_USED").length, 1);
});

test("a settled payment cannot be replayed", async () => {
  const h = harness();
  const tok = token("pay-7");
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("re-encoding a payment with different empty signature slots shares its claim", async () => {
  const a = token("pay-8", 0);
  const b = token("pay-8", 9);
  assert.notEqual(a, b);
  const h = harness();
  assert.equal((await h.handler({}, paid(a))).isError, undefined);
  assert.equal(errorCode(await h.handler({}, paid(b))), "PAYMENT_ALREADY_USED");
});

test("different payments are independent", async () => {
  const h = harness();
  assert.equal((await h.handler({}, paid(token("pay-9a")))).isError, undefined);
  assert.equal((await h.handler({}, paid(token("pay-9b")))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 2);
});

test("settled claims survive a restart; released ones do not block", async () => {
  const claimsDir = tempDir();
  const settledTok = token("pay-10");
  const first = harness({ claimsDir });
  assert.equal((await first.handler({}, paid(settledTok))).isError, undefined);
  const failedTok = token("pay-10b");
  const failing = harness({
    claimsDir,
    settle: async () => ({ success: false, errorReason: "insufficient_funds", transaction: "", network: "solana" }),
  });
  assert.equal(errorCode(await failing.handler({}, paid(failedTok))), "insufficient_funds");
  const restarted = harness({ claimsDir });
  assert.equal(errorCode(await restarted.handler({}, paid(settledTok))), "PAYMENT_ALREADY_USED");
  assert.equal((await restarted.handler({}, paid(failedTok))).isError, undefined);
  const claimFiles = fs.readdirSync(claimsDir).filter((n) => n.endsWith(".claim"));
  assert.equal(claimFiles.length, 2);
});

test("a claim directory removed while the server runs is recreated", async () => {
  const h = harness();
  fs.rmSync(h.claimsDir, { recursive: true, force: true });
  const result = await h.handler({}, paid(token("pay-11a")));
  assert.equal(result.isError, undefined);
  assert.ok(fs.existsSync(h.claimsDir));
  assert.equal(errorCode(await h.handler({}, paid(token("pay-11a")))), "PAYMENT_ALREADY_USED");
});

test("an unwritable claim store refuses the payment before any facilitator call", async () => {
  const h = harness();
  fs.rmSync(h.claimsDir, { recursive: true, force: true });
  fs.writeFileSync(h.claimsDir, "not a directory");
  const result = await h.handler({}, paid(token("pay-11")));
  assert.equal(errorCode(result), "PAYMENT_CLAIM_UNAVAILABLE");
  assert.deepEqual(paymentEvents(h.events), []);
  assert.ok(h.logs.some((l) => l.includes("claim store unavailable")));
});

test("a tool that fails after settlement is reported as paid and logged", async () => {
  const h = harness({ toolResult: async () => ({ isError: true, content: [{ type: "text", text: "Error: upstream down" }] }) });
  const result = await h.handler({}, paid(token("pay-12")));
  assert.equal(result.isError, true);
  const response = result._meta?.["x402/payment-response"] as { success: boolean; transaction: string };
  assert.equal(response.success, true);
  assert.equal(response.transaction, "sig-1");
  assert.ok(h.logs.some((l) => l.includes("failed after settlement") && l.includes("sig-1")));
});

test("a tool that throws after settlement is reported as paid", async () => {
  const h = harness({
    toolResult: async () => {
      throw new Error("boom");
    },
  });
  const result = await h.handler({}, paid(token("pay-13")));
  assert.equal(result.isError, true);
  assert.match(result.content[0].text ?? "", /Tool execution failed: Error: boom/);
  assert.ok(result._meta?.["x402/payment-response"]);
});

test("a precheck refusal comes before any payment is asked for or taken", async () => {
  const h = harness({ precheck: (args) => (args.x === "bad" ? "url not allowed" : null) });
  const unpaid = await h.handler({ x: "bad" }, {});
  assert.equal(unpaid.content[0].text, "Error: url not allowed");
  assert.equal(unpaid._meta, undefined);
  const tok = token("pay-14");
  const refused = await h.handler({ x: "bad" }, paid(tok));
  assert.equal(refused.content[0].text, "Error: url not allowed");
  assert.deepEqual(h.events, []);
  assert.equal((await h.handler({ x: "good" }, paid(tok))).isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle", "tool"]);
});

test("a transaction without a message is refused before any facilitator call", async () => {
  const h = harness();
  const noSigs = encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: Buffer.from([0, 1, 2]).toString("base64") } });
  assert.equal(errorCode(await h.handler({}, paid(noSigs))), "INVALID_PAYMENT");
  const truncated = encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: Buffer.concat([Buffer.from([2]), Buffer.alloc(100)]).toString("base64") } });
  assert.equal(errorCode(await h.handler({}, paid(truncated))), "INVALID_PAYMENT");
  assert.equal(errorCode(await h.handler({}, paid("not-a-payment"))), "INVALID_PAYMENT");
  assert.deepEqual(paymentEvents(h.events), []);
});

test("the claim key ignores signature slots and covers the message", () => {
  const key = (tx: string) =>
    paymentClaimKey({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: tx } });
  assert.equal(key(txBase64("m", 0)), key(txBase64("m", 5)));
  assert.notEqual(key(txBase64("m")), key(txBase64("n")));
  assert.match(key(txBase64("m")) ?? "", /^svm-[0-9a-f]{64}$/);
});

test("only an svm recipient is accepted", () => {
  assert.throws(
    () => createSettleFirstPaidTools({ ...CONFIG, recipient: {} as unknown as SettleFirstConfig["recipient"] }, { claimsDir: tempDir() }),
    /only an svm recipient/,
  );
});
