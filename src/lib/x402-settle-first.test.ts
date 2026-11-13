import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  address,
  appendTransactionMessageInstructions,
  blockhash,
  createNoopSigner,
  createTransactionMessage,
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  partiallySignTransactionMessageWithSigners,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from "@solana-program/compute-budget";
import { getCreateAssociatedTokenInstruction, getTransferCheckedInstruction, TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";
import { TOKEN_2022_PROGRAM_ADDRESS } from "@solana-program/token-2022";
import { decodePayment, encodePayment } from "x402/schemes";
import type { VerifyResponse } from "x402/types";
import {
  ClaimStore,
  classifySettle,
  createSettleFirstPaidTools,
  MAX_PAYMENT_TOKEN_LENGTH,
  paidCallId,
  paymentAuthority,
  paymentClaimKey,
  paymentTokenAuthority,
  postSettle,
  PREFLIGHT_FAILED,
  readResumeCode,
  RESUME_HEADER,
  RESUME_META_KEY,
  SETTLEMENT_UNRESOLVED,
  type FacilitatorClient,
  type SettleFirstConfig,
  type SettleReply,
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

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}
function b58decode(text: string): Buffer {
  let n = 0n;
  for (const ch of text) n = n * 58n + BigInt(B58.indexOf(ch));
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of text) {
    if (ch !== "1") break;
    out.unshift(0);
  }
  return Buffer.from(out);
}
const key32 = (seed: string) => createHash("sha256").update(seed).digest();
const walletOf = (name: string) => b58encode(key32(name));
const TOKEN_PROGRAM = b58decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

interface TxShape {
  payer?: string;
  feePayerSeed?: string;
  authorityIndex?: number;
  transfers?: number;
  authorityIsSigner?: boolean;
  program?: Buffer;
}

/**
 * A v0 Solana wire transaction shaped like an x402 "exact" payment: the fee
 * payer and the paying wallet sign, and one token TransferChecked moves USDC
 * from the paying wallet. `seed` varies the blockhash, so each seed is a
 * different payment; `slotFill` fills the (unchecked) signature bytes.
 */
function txBase64(seed: string, slotFill = 0, shape: TxShape = {}): string {
  const payer = shape.payer ?? "payer-wallet";
  const signers = shape.authorityIsSigner === false ? 1 : 2;
  const keys = [key32(shape.feePayerSeed ?? "fee-payer"), key32(payer), key32(`source-${payer}`), key32("destination"), key32("mint"), shape.program ?? TOKEN_PROGRAM];
  const transferData = Buffer.concat([Buffer.from([12]), Buffer.alloc(8), Buffer.from([6])]);
  const transfer = Buffer.concat([Buffer.from([5, 4, 2, 4, 3, shape.authorityIndex ?? 1, transferData.length]), transferData]);
  const transfers = Array.from({ length: shape.transfers ?? 1 }, () => transfer);
  const message = Buffer.concat([
    Buffer.from([0x80, signers, 0, 2, keys.length]),
    ...keys,
    key32(`blockhash-${seed}`),
    Buffer.from([transfers.length]),
    ...transfers,
    Buffer.from([0]),
  ]);
  return Buffer.concat([Buffer.from([signers]), Buffer.alloc(64 * signers, slotFill), message]).toString("base64");
}

function token(seed: string, slotFill = 0, shape: TxShape = {}): string {
  return encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: txBase64(seed, slotFill, shape) } });
}

function paid(tok: string): { _meta: Record<string, unknown> } {
  return { _meta: { "x402/payment": tok } };
}

const RESUME_CODE = /^[A-Za-z0-9_-]{43}$/;
const sha256hex = (text: string) => createHash("sha256").update(text).digest("hex");
/** The resume code an answer that leaves the outcome open gave its caller. */
function resumeCodeOf(result: ToolResult): string {
  const code = (result._meta?.["x402/error"] as { resumeCode?: unknown } | undefined)?.resumeCode;
  assert.match(String(code), RESUME_CODE, "the answer carries a resume code");
  return code as string;
}
/** The same payment presented again, with the resume code its unresolved answer gave (or the code given). */
function resume(tok: string, from: ToolResult | string): { _meta: Record<string, unknown> } {
  return { _meta: { "x402/payment": tok, "x402/resume": typeof from === "string" ? from : resumeCodeOf(from) } };
}
/** A well-formed resume code that is no payment's. */
const WRONG_CODE = "w".repeat(43);

interface Harness {
  handler: Handler;
  events: string[];
  logs: string[];
  extras: unknown[];
  claimsDir: string;
  /** The server's clock. Waiting between settle requests moves it; nothing else does. */
  clock: { now: number };
  /** Every wait between two settle requests, in milliseconds. */
  sleeps: number[];
}

function harness(opts: {
  verify?: () => Promise<VerifyResponse>;
  /** The facilitator's answer to a settle request (as HTTP 200); a rejection is a request that got no reply. */
  settle?: () => Promise<SettleReply>;
  claimsDir?: string;
  /** The paid tool's name (default "echo") and description: two servers share a claim directory, not their tools. */
  toolName?: string;
  description?: string;
  toolResult?: () => Promise<ToolResult>;
  precheck?: (args: { x?: string }) => string | null;
  preflight?: (args: { x?: string }) => Promise<string | null> | string | null;
  events?: string[];
  /** A facilitator that is given a settle request's exact body and may answer with any HTTP status. */
  settleBody?: (body: string, timeoutMs: number) => Promise<SettleReply>;
  clock?: { now: number };
  /** Waiting between settle requests does not move the clock. */
  stoppedClock?: boolean;
  /** The facilitator's list of supported kinds, in place of the usual one. */
  supported?: () => Promise<{ kinds: Array<{ scheme: string; network: string; extra?: Record<string, unknown> }> }>;
  verifyTimeoutMs?: number;
  supportedTimeoutMs?: number;
} = {}): Harness {
  const events: string[] = opts.events ?? [];
  const logs: string[] = [];
  const extras: unknown[] = [];
  const sleeps: number[] = [];
  const clock = opts.clock ?? { now: Date.now() };
  const settleBody = opts.settleBody;
  const claimsDir = opts.claimsDir ?? tempDir();
  const facilitator: FacilitatorClient = {
    supported: async () => {
      events.push("supported");
      if (opts.supported) return opts.supported();
      return { kinds: [{ scheme: "exact", network: "solana", extra: { feePayer: walletOf("fee-payer") } }] };
    },
    verify: async () => {
      events.push("verify");
      return opts.verify ? opts.verify() : { isValid: true, payer: "Payer1111" };
    },
    settleBody: async (body: string, timeoutMs: number) => {
      events.push("settle");
      if (settleBody) return settleBody(body, timeoutMs);
      return opts.settle ? opts.settle() : { success: true, transaction: "sig-1", network: "solana", payer: "Payer1111" };
    },
  };
  const settleFirst = createSettleFirstPaidTools(CONFIG, {
    facilitator,
    claimsDir,
    log: (line) => logs.push(line),
    info: (line) => logs.push(line),
    now: () => clock.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      if (!opts.stoppedClock) clock.now += ms;
    },
    ...(opts.verifyTimeoutMs !== undefined ? { verifyTimeoutMs: opts.verifyTimeoutMs } : {}),
    ...(opts.supportedTimeoutMs !== undefined ? { supportedTimeoutMs: opts.supportedTimeoutMs } : {}),
  });
  const tools = new Map<string, Handler>();
  const server = {
    tool: (...args: unknown[]) => {
      tools.set(args[0] as string, args[4] as Handler);
    },
  };
  const toolName = opts.toolName ?? "echo";
  settleFirst(server)(
    toolName,
    opts.description ?? "Echo",
    "$0.01",
    {},
    {},
    async (_args: { x?: string }, extra: unknown) => {
      events.push("tool");
      extras.push(extra);
      return opts.toolResult ? opts.toolResult() : { content: [{ type: "text", text: "ok" }] };
    },
    {
      precheck: opts.precheck,
      ...(opts.preflight
        ? {
            preflight: async (args: { x?: string }) => {
              events.push("preflight");
              return opts.preflight?.(args) ?? null;
            },
          }
        : {}),
    },
  );
  const handler = tools.get(toolName);
  assert.ok(handler, "tool registered");
  return { handler, events, logs, extras, claimsDir, clock, sleeps };
}

/** Shaped like a Solana transaction signature, which is what an unresolved settlement may name to its caller. */
const SIGNATURE = "4".repeat(44) + "A".repeat(44);
const PENDING: SettleReply = { success: false, errorReason: "settlement_pending", transaction: SIGNATURE, network: "solana", payer: "", httpStatus: 200 };
const SETTLED: SettleReply = { success: true, transaction: SIGNATURE, network: "solana", payer: "Payer1111", httpStatus: 200 };

function claimFiles(dir: string): string[] {
  return fs.readdirSync(dir).filter((n) => n.endsWith(".claim"));
}
function onlyClaim(dir: string): Record<string, unknown> {
  const files = claimFiles(dir);
  assert.equal(files.length, 1, "one claim file");
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8")) as Record<string, unknown>;
}
/** Nothing a claim change leaves behind when it is done: no lock, no half-written record. */
function leftovers(dir: string): string[] {
  return fs.readdirSync(dir).filter((n) => !n.endsWith(".claim"));
}
const x402Error = (result: ToolResult) => (result._meta?.["x402/error"] ?? {}) as Record<string, unknown>;
/** Turns the one claim into a record as the version before resume codes wrote it: no resume-code hash. */
function dropResumeHash(dir: string): void {
  const file = path.join(dir, claimFiles(dir)[0]);
  const record = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
  assert.match(String(record.rc), /^[0-9a-f]{64}$/, "the record held a resume-code hash");
  delete record.rc;
  fs.writeFileSync(file, JSON.stringify(record));
}
/** The answer to a call that may not resume a settlement: no new payment offered, no code given, and why. */
function assertNotResumed(result: ToolResult): void {
  assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
  assert.equal(x402Error(result).accepts, undefined);
  assert.equal(x402Error(result).resumeCode, undefined, "a call without the code is given none");
  assert.match(String(x402Error(result).message), /did not present the payment's resume code/);
  assert.match(String(x402Error(result).message), /Do not send a new payment/);
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
  // The transaction's transfer authority, not the facilitator's "payer" field ("Payer1111" in this fake).
  assert.equal(settlement.payer, walletOf("payer-wallet"));
  assert.equal((result._meta?.["x402/payment-response"] as X402Settlement).payer, walletOf("payer-wallet"));
});

test("a payment the facilitator definitely refuses never runs the tool, is logged, and can be presented again", async () => {
  let attempt = 0;
  const h = harness({
    settle: async () =>
      ++attempt === 1
        ? { success: false, errorReason: "insufficient_funds", transaction: "", network: "solana" }
        : { success: true, transaction: "sig-2", network: "solana", payer: "Payer1111" },
  });
  const tok = token("pay-2");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), "insufficient_funds");
  assert.ok(Array.isArray(x402Error(first).accepts), "a refused payment is offered a new one");
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle"]);
  assert.ok(h.logs.some((l) => l.includes("settle failed") && l.includes("insufficient_funds")));
  assert.deepEqual(claimFiles(h.claimsDir), []);
  const second = await h.handler({}, paid(tok));
  assert.equal(second.isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle", "verify", "settle", "tool"]);
  assert.deepEqual(h.sleeps, [], "a definite answer is not asked for twice");
});

test("a settlement the facilitator has not finished is not a failure: the same call asks again and runs the tool once it settled", async () => {
  let attempt = 0;
  const h = harness({
    settle: async () =>
      ++attempt === 1
        ? { success: false, errorReason: "settle_exact_svm_transaction_confirmation_timed_out", transaction: "sig-maybe", network: "solana" }
        : { success: true, transaction: "sig-2", network: "solana", payer: "Payer1111" },
  });
  const result = await h.handler({}, paid(token("pay-2b")));
  assert.equal(result.isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle", "settle", "tool"]);
  assert.equal((result._meta?.["x402/payment-response"] as X402Settlement).transaction, "sig-2");
  assert.deepEqual(h.sleeps, [2000]);
  assert.equal(onlyClaim(h.claimsDir).s, "settled");
  assert.deepEqual(leftovers(h.claimsDir), []);
});

test("a settle request that gets no reply is not a failure either: the same call asks again", async () => {
  let attempt = 0;
  const h = harness({
    settle: async () => {
      if (++attempt === 1) throw new Error("Failed to settle payment: 502 Bad Gateway");
      return { success: true, transaction: "sig-3", network: "solana", payer: "Payer1111" };
    },
  });
  const tok = token("pay-3");
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "settle", "settle", "tool"]);
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("a settlement still unresolved when the call's time is up: claim kept, outcome reported as unknown, no new payment offered", async () => {
  const bodies: string[] = [];
  const timeouts: number[] = [];
  const h = harness({
    settleBody: async (body, timeoutMs) => {
      bodies.push(body);
      timeouts.push(timeoutMs);
      return PENDING;
    },
  });
  const tok = token("pay-u1");
  const result = await h.handler({ x: "a" }, paid(tok));
  assert.equal(result.isError, true);
  assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
  const error = x402Error(result);
  assert.equal(error.accepts, undefined, "no accepts: a client that pays whatever is offered must not pay twice");
  assert.equal(error.transaction, SIGNATURE);
  assert.equal(error.retryAfterSeconds, 30);
  assert.match(String(error.message), /Do not send a new payment/);
  assert.match(String(error.message), /resume code given here as _meta\["x402\/resume"\] \(or the X-PAYMENT-RESUME header\)/);
  const code = resumeCodeOf(result);
  assert.equal(result._meta?.["x402/payment-response"], undefined);
  assert.equal(h.events.includes("tool"), false);
  // Asked 7 times in 45 seconds, every time with the identical body, each request given what is left of the time.
  assert.deepEqual(h.sleeps, [2000, 3000, 5000, 10000, 10000, 10000]);
  assert.equal(bodies.length, 7);
  assert.equal(new Set(bodies).size, 1);
  assert.deepEqual(timeouts, [45000, 43000, 40000, 35000, 25000, 15000, 5000]);
  const sent = JSON.parse(bodies[0]) as { x402Version: number; paymentPayload: { payload: { transaction: string } }; paymentRequirements: { payTo: string } };
  assert.equal(sent.x402Version, 1);
  assert.equal(sent.paymentPayload.payload.transaction, txBase64("pay-u1"));
  assert.equal(sent.paymentRequirements.payTo, CONFIG.recipient.svm.address);
  assert.ok(h.logs.some((l) => l.includes("settlement unresolved, claim kept, tool not run") && l.includes("settlement_pending") && l.includes(SIGNATURE)));
  const claim = onlyClaim(h.claimsDir);
  assert.equal(claim.s, "unresolved");
  assert.equal(claim.tx, SIGNATURE);
  assert.equal(claim.body, bodies[0]);
  assert.equal(claim.call, paidCallId("echo", { x: "a" }));
  // The claim keeps the code's SHA-256, and the code itself is nowhere on disk or in the log.
  assert.equal(claim.rc, sha256hex(code));
  assert.equal(fs.readFileSync(path.join(h.claimsDir, claimFiles(h.claimsDir)[0]), "utf8").includes(code), false);
  assert.equal(h.logs.some((l) => l.includes(code)), false);
  assert.deepEqual(leftovers(h.claimsDir), []);
});

test("presenting an unresolved payment with the same call again asks once more, without a new verify, and runs the tool when it settled", async () => {
  let reply = PENDING;
  const bodies: string[] = [];
  const h = harness({
    settleBody: async (body) => {
      bodies.push(body);
      return reply;
    },
  });
  const tok = token("pay-u2");
  const first = await h.handler({ x: "a" }, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  const asked = bodies.length;
  h.events.length = 0;
  reply = SETTLED;
  const again = await h.handler({ x: "a" }, resume(tok, first));
  assert.equal(again.isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["settle", "tool"]);
  assert.equal(bodies.length, asked + 1);
  assert.equal(new Set(bodies).size, 1, "the later request carries the first request's body");
  const response = again._meta?.["x402/payment-response"] as X402Settlement & { success: boolean };
  assert.equal(response.success, true);
  assert.equal(response.transaction, SIGNATURE);
  assert.equal(response.payer, walletOf("payer-wallet"));
  assert.ok(h.logs.some((l) => l.includes("asking again about an unresolved settlement")));
  assert.equal(onlyClaim(h.claimsDir).s, "settled");
  assert.equal(errorCode(await h.handler({ x: "a" }, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(errorCode(await h.handler({ x: "a" }, resume(tok, first))), "PAYMENT_ALREADY_USED", "the code is no use once the payment is settled");
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("an unresolved payment is resumed only by the call that started it: other arguments are refused and the facilitator is not asked", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-u3");
  const first = await h.handler({ x: "a" }, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  const asked = h.events.filter((e) => e === "settle").length;
  reply = SETTLED;
  assert.equal(errorCode(await h.handler({ x: "b" }, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  // The resume code is the payment's and the call's: with other arguments it opens nothing.
  assert.equal(errorCode(await h.handler({ x: "b" }, resume(tok, first))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "settle").length, asked);
  assert.equal(h.events.includes("tool"), false);
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
  // The same arguments in another key order are the same call.
  assert.equal(paidCallId("echo", { a: 1, b: [{ d: 1, c: 2 }] }), paidCallId("echo", { b: [{ c: 2, d: 1 }], a: 1 }));
  assert.notEqual(paidCallId("echo", { a: 1 }), paidCallId("other", { a: 1 }));
  assert.notEqual(paidCallId("echo", { a: 1 }), paidCallId("echo", { a: "1" }));
});

test("when the facilitator's recorded outcome is a failure, the claim is released and a new payment is offered", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-u4");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  reply = { success: false, errorReason: "invalid_transaction_state", transaction: SIGNATURE, network: "solana", payer: "", httpStatus: 200 };
  const failed = await h.handler({}, resume(tok, first));
  assert.equal(errorCode(failed), "invalid_transaction_state");
  assert.ok(Array.isArray(x402Error(failed).accepts));
  assert.equal(h.events.includes("tool"), false);
  assert.deepEqual(claimFiles(h.claimsDir), []);
  assert.deepEqual(leftovers(h.claimsDir), []);
});

test("a refusal that is not HTTP 200 ends a payment's first settle request, but says nothing about an earlier one", async () => {
  const refusal: SettleReply = { success: false, errorReason: "free_tier_exhausted", transaction: "", network: "solana", payer: "", httpStatus: 403 };
  const first = harness({ settleBody: async () => refusal });
  const refused = await first.handler({}, paid(token("pay-u5")));
  assert.equal(errorCode(refused), "free_tier_exhausted");
  assert.deepEqual(claimFiles(first.claimsDir), []);
  assert.equal(first.events.filter((e) => e === "settle").length, 1);

  let reply = PENDING;
  const later = harness({ settleBody: async () => reply });
  const tok = token("pay-u5b");
  const unresolved = await later.handler({}, paid(tok));
  assert.equal(errorCode(unresolved), SETTLEMENT_UNRESOLVED);
  reply = refusal;
  const asked = later.events.filter((e) => e === "settle").length;
  const again = await later.handler({}, resume(tok, unresolved));
  assert.equal(errorCode(again), SETTLEMENT_UNRESOLVED);
  assert.ok(later.events.filter((e) => e === "settle").length > asked, "the facilitator was asked again");
  assert.equal(resumeCodeOf(again), resumeCodeOf(unresolved), "the payment keeps its resume code");
  assert.equal(onlyClaim(later.claimsDir).s, "unresolved");
  assert.equal(onlyClaim(later.claimsDir).tx, SIGNATURE, "the transaction named earlier is kept");
  assert.equal(later.events.includes("tool"), false);
});

test("an unresolved payment is not resumed without its resume code, whoever presents it with the right call", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-rc1");
  const first = await h.handler({ x: "a" }, paid(tok));
  const code = resumeCodeOf(first);
  // A second payment's code is no use for the first.
  const other = await h.handler({ x: "a" }, paid(token("pay-rc1-other")));
  const otherCode = resumeCodeOf(other);
  assert.notEqual(otherCode, code);
  const file = path.join(h.claimsDir, `${paymentClaimKey(decodePayment(tok))}.claim`);
  const before = fs.readFileSync(file, "utf8");
  const asked = h.events.filter((e) => e === "settle").length;
  reply = SETTLED;

  assertNotResumed(await h.handler({ x: "a" }, paid(tok)));
  assertNotResumed(await h.handler({ x: "a" }, resume(tok, WRONG_CODE)));
  assertNotResumed(await h.handler({ x: "a" }, resume(tok, otherCode)));
  assertNotResumed(await h.handler({ x: "a" }, resume(tok, code.slice(0, 42))));
  assertNotResumed(await h.handler({ x: "a" }, resume(tok, code + "A")));
  assertNotResumed(await h.handler({ x: "a" }, resume(tok, sha256hex(code))));
  assertNotResumed(await h.handler({ x: "a" }, { _meta: { "x402/payment": tok, "x402/resume": { code } } }));
  assert.equal(h.events.filter((e) => e === "settle").length, asked, "the facilitator is not asked");
  assert.equal(h.events.includes("tool"), false);
  assert.equal(fs.readFileSync(file, "utf8"), before, "the claim is untouched");
  assert.ok(h.logs.some((l) => l.includes("an unresolved settlement was not resumed: no resume code")));
  assert.ok(h.logs.some((l) => l.includes("an unresolved settlement was not resumed: wrong resume code")));
  assert.equal(h.logs.some((l) => l.includes(code) || l.includes(otherCode) || l.includes(WRONG_CODE)), false, "no code is ever logged");

  const resumed = await h.handler({ x: "a" }, resume(tok, code));
  assert.equal(resumed.isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("the resume code is read from _meta or the X-PAYMENT-RESUME header, and only when it is shaped like one", async () => {
  const code = "b".repeat(43);
  assert.equal(RESUME_META_KEY, "x402/resume");
  assert.equal(RESUME_HEADER, "X-PAYMENT-RESUME");
  assert.equal(readResumeCode({ _meta: { "x402/resume": code } }), code);
  assert.equal(readResumeCode({ requestInfo: { headers: new Headers({ "x-payment-resume": code }) } }), code);
  assert.equal(readResumeCode({ requestInfo: { headers: { "X-PAYMENT-RESUME": code } } }), code);
  assert.equal(readResumeCode({ requestInfo: { headers: { "x-payment-resume": code } } }), code);
  assert.equal(readResumeCode({ _meta: { "x402/resume": code }, requestInfo: { headers: { "x-payment-resume": "c".repeat(43) } } }), code);
  // A value in _meta that is not shaped like a code does not hide the one in the header.
  for (const junk of ["", "short", 42, null]) {
    assert.equal(readResumeCode({ _meta: { "x402/resume": junk }, requestInfo: { headers: { "x-payment-resume": code } } }), code, JSON.stringify(junk));
  }
  for (const bad of ["", "short", code + "b", code.slice(1) + "=", code.slice(1) + "/", " " + code.slice(1), 42, null, { code }, [code]]) {
    assert.equal(readResumeCode({ _meta: { "x402/resume": bad } }), undefined, JSON.stringify(bad));
  }
  assert.equal(readResumeCode({ requestInfo: { headers: { "x-payment-resume": [code] } } }), undefined);
  assert.equal(readResumeCode({}), undefined);
  assert.equal(readResumeCode(undefined), undefined);

  // Through a real call: the header resumes the settlement as _meta does.
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-rc2");
  const first = await h.handler({}, paid(tok));
  reply = SETTLED;
  const viaHeader = await h.handler({}, { _meta: { "x402/payment": tok }, requestInfo: { headers: new Headers({ "X-PAYMENT-RESUME": resumeCodeOf(first) }) } });
  assert.equal(viaHeader.isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("a record whose resume-code hash cannot be read asks for no code and offers no new payment: nobody resumes it", async () => {
  const h = harness({ preflight: () => null });
  const tok = token("pay-rc3");
  const file = path.join(h.claimsDir, `${paymentClaimKey(decodePayment(tok))}.claim`);
  const call = paidCallId("echo", {});
  const record = (rc: unknown) => JSON.stringify({ s: "unresolved", t: h.clock.now, f: h.clock.now, call, body: "{}", rc });
  for (const rc of ["", "not-a-hash", "A".repeat(64), "a".repeat(63), 7, null, { hash: "a".repeat(64) }]) {
    fs.writeFileSync(file, record(rc));
    for (const extra of [paid(tok), resume(tok, WRONG_CODE), resume(tok, typeof rc === "string" ? rc : "x")]) {
      const result = await h.handler({}, extra);
      assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED, JSON.stringify(rc));
      assert.equal(x402Error(result).accepts, undefined, "the payment may be taken: no new one is offered");
      assert.equal(x402Error(result).resumeCode, undefined);
      assert.match(String(x402Error(result).message), /cannot read this payment's record right now/);
    }
    assert.equal(fs.readFileSync(file, "utf8"), record(rc), "the claim is untouched");
  }
  assert.deepEqual(paymentEvents(h.events), [], "nothing was asked of the facilitator, and the readiness check did not run");
  // Other arguments, and a settlement past its 23 hours, are a used payment as for any record.
  assert.equal(errorCode(await h.handler({ x: "other" }, paid(tok))), "PAYMENT_ALREADY_USED");
  h.clock.now += 23 * 60 * 60 * 1000;
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  h.clock.now -= 23 * 60 * 60 * 1000;
  // The control: the same record with a readable hash is an unresolved settlement that wants its code.
  fs.writeFileSync(file, record(sha256hex("c".repeat(43))));
  assertNotResumed(await h.handler({}, paid(tok)));
  assert.deepEqual(paymentEvents(h.events), []);
  assert.equal((await h.handler({}, resume(tok, "c".repeat(43)))).isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["preflight", "settle", "tool"], "with the code, the facilitator is asked and the call runs");
});

test("the resume code is checked again when the settlement is taken over: a record that changed during the readiness check is not resumed on the first look", async () => {
  // The first look at the claim and the takeover are two steps with the readiness check between them. Whatever the
  // claim says at the takeover decides.
  for (const legacy of [false, true]) {
    const claimsDir = tempDir();
    const events: string[] = [];
    const first = harness({ claimsDir, events, settleBody: async () => PENDING });
    const tok = token(`pay-rc4-${legacy}`);
    const unresolved = await first.handler({}, paid(tok));
    const code = resumeCodeOf(unresolved);
    if (legacy) dropResumeHash(claimsDir);
    const file = path.join(claimsDir, claimFiles(claimsDir)[0]);
    let open: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const waiting = harness({ claimsDir, events, settleBody: async () => SETTLED, preflight: () => gate.then(() => null) });
    const asked = events.filter((e) => e === "settle").length;
    // With its code (or, for a record from before resume codes, without one) the call passes the first look.
    const call = waiting.handler({}, legacy ? paid(tok) : resume(tok, code));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(events.filter((e) => e === "preflight").length, 1, "the first look let it through to the readiness check");
    // Meanwhile the claim comes to hold another code's hash.
    const record = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
    fs.writeFileSync(file, JSON.stringify({ ...record, rc: sha256hex("z".repeat(43)) }));
    const changed = fs.readFileSync(file, "utf8");
    open();
    assertNotResumed(await call);
    assert.equal(events.filter((e) => e === "settle").length, asked, "the facilitator is not asked");
    assert.equal(events.includes("tool"), false);
    assert.equal(fs.readFileSync(file, "utf8"), changed, "the claim is untouched");
    assert.deepEqual(leftovers(claimsDir), []);
  }
});

test("a caller may choose the resume code itself and send it with the first call: the answer gives the same code back", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-own1");
  const mine = "m".repeat(43);
  const first = await h.handler({ x: "a" }, resume(tok, mine));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  assert.equal(resumeCodeOf(first), mine);
  assert.equal(onlyClaim(h.claimsDir).rc, sha256hex(mine));
  assert.equal(fs.readFileSync(path.join(h.claimsDir, claimFiles(h.claimsDir)[0]), "utf8").includes(mine), false);
  assert.equal(h.logs.some((l) => l.includes(mine)), false, "a caller's own code is not logged either");
  reply = SETTLED;
  assertNotResumed(await h.handler({ x: "a" }, paid(tok)));
  assertNotResumed(await h.handler({ x: "a" }, resume(tok, WRONG_CODE)));
  assert.equal((await h.handler({ x: "a" }, resume(tok, mine))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);

  // The header carries it as well, and a value that is not shaped like a code is not taken: the server makes one.
  const viaHeader = harness({ settleBody: async () => PENDING });
  const headerAnswer = await viaHeader.handler({}, { _meta: { "x402/payment": token("pay-own2") }, requestInfo: { headers: new Headers({ "X-PAYMENT-RESUME": mine }) } });
  assert.equal(resumeCodeOf(headerAnswer), mine);
  const misshapen = harness({ settleBody: async () => PENDING });
  const made = resumeCodeOf(await misshapen.handler({}, resume(token("pay-own3"), "my-password")));
  assert.notEqual(made, "my-password");
  assert.equal(onlyClaim(misshapen.claimsDir).rc, sha256hex(made));
  // The claim store makes the same check itself, whatever its caller lets through.
  const store = new ClaimStore(tempDir(), () => Date.now(), () => {});
  assert.equal(store.tryClaim("svm-direct", "call"), true);
  const direct = store.markSettling("svm-direct", "call", "{}", "my-password");
  assert.match(String(direct?.code), RESUME_CODE);
  assert.equal(store.markSettling("svm-direct", "call", "{}", mine)?.code, mine);
  // A payment that settles at once needs no code: sending one changes nothing.
  const plain = harness();
  assert.equal((await plain.handler({}, resume(token("pay-own4"), mine))).isError, undefined);
  assert.deepEqual(paymentEvents(plain.events), ["verify", "settle", "tool"]);
});

test("a call that is cut off before it answers is resumed with the caller's own code, and with nothing else", async () => {
  const claimsDir = tempDir();
  const clock = { now: Date.now() };
  const events: string[] = [];
  let answerFirst: (reply: SettleReply) => void = () => {};
  const hung = new Promise<SettleReply>((resolve) => {
    answerFirst = resolve;
  });
  const first = harness({ claimsDir, clock, events, settle: () => hung });
  const tok = token("pay-own5");
  const mine = "n".repeat(43);
  // The call's answer never reaches the caller (here: it is still waiting for the facilitator).
  const firstCall = first.handler({ x: "a" }, resume(tok, mine));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(onlyClaim(claimsDir).s, "settling");
  assert.equal(onlyClaim(claimsDir).rc, sha256hex(mine));

  const second = harness({ claimsDir, clock, events });
  const early = await second.handler({ x: "a" }, resume(tok, mine));
  assert.match(String(x402Error(early).message), /still in progress/);
  assert.match(String(x402Error(early).message), /resume code of your own, present the same payment, the same call and that code again in ten minutes/);
  assert.equal(x402Error(early).accepts, undefined);
  clock.now += 10 * 60 * 1000;
  assertNotResumed(await second.handler({ x: "a" }, paid(tok)));
  assertNotResumed(await second.handler({ x: "a" }, resume(tok, WRONG_CODE)));
  assert.equal(errorCode(await second.handler({ x: "b" }, resume(tok, mine))), "PAYMENT_ALREADY_USED", "the code is for this call only");
  assert.equal(events.filter((e) => e === "settle").length, 1);
  const late = await second.handler({ x: "a" }, resume(tok, mine));
  assert.equal(late.isError, undefined);
  assert.equal(events.filter((e) => e === "tool").length, 1);
  assert.equal(onlyClaim(claimsDir).s, "settled");

  // The first call's answer comes after all: it no longer owns the settlement and runs nothing.
  answerFirst({ success: true, transaction: "sig-late", network: "solana", payer: "Payer1111" });
  const stale = await firstCall;
  assert.equal(errorCode(stale), SETTLEMENT_UNRESOLVED);
  assert.equal(events.filter((e) => e === "tool").length, 1, "one payment, one tool run");
});

test("a verify that does not answer in time is a refusal with nothing taken, and the payment can be presented again", async () => {
  let hang = true;
  const h = harness({
    verifyTimeoutMs: 40,
    verify: () => (hang ? new Promise<VerifyResponse>(() => {}) : Promise.resolve({ isValid: true, payer: "Payer1111" })),
  });
  const tok = token("pay-vt1");
  const started = Date.now();
  const refused = await h.handler({}, paid(tok));
  assert.ok(Date.now() - started < 5_000, "the call did not wait for the facilitator");
  assert.equal(errorCode(refused), "VERIFY_FAILED");
  assert.ok(Array.isArray(x402Error(refused).accepts), "nothing was sent for settlement, so a new payment may be offered");
  assert.deepEqual(paymentEvents(h.events), ["verify"]);
  assert.deepEqual(claimFiles(h.claimsDir), [], "the claim is released");
  assert.ok(h.logs.some((l) => l.includes("verify: no answer in 40 ms, payment refused unpaid")));
  hang = false;
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "verify", "settle", "tool"]);
});

test("a list of supported kinds that does not come in time refuses the call before any payment, and is asked for again", async () => {
  let hang = true;
  const kinds = { kinds: [{ scheme: "exact", network: "solana", extra: { feePayer: walletOf("fee-payer") } }] };
  const h = harness({ supportedTimeoutMs: 40, supported: () => (hang ? new Promise<typeof kinds>(() => {}) : Promise.resolve(kinds)) });
  const tok = token("pay-st1");
  const refused = await h.handler({}, paid(tok));
  assert.equal(errorCode(refused), "PRICE_COMPUTE_FAILED");
  assert.equal(x402Error(refused).accepts, undefined);
  assert.deepEqual(h.events, ["supported"]);
  assert.deepEqual(claimFiles(h.claimsDir), []);
  hang = false;
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.deepEqual(h.events, ["supported", "supported", "verify", "settle", "tool"]);
});

test("the settle requests stop 50 seconds after the call came in, whatever verify and the readiness check took of it", async () => {
  const timeouts: number[] = [];
  const h = harness({
    verify: async () => {
      h.clock.now += 14_000;
      return { isValid: true, payer: "Payer1111" };
    },
    preflight: () => {
      h.clock.now += 30_000;
      return null;
    },
    settleBody: async (_body, timeoutMs) => {
      timeouts.push(timeoutMs);
      return PENDING;
    },
  });
  const started = h.clock.now;
  const result = await h.handler({}, paid(token("pay-cb1")));
  assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
  resumeCodeOf(result);
  // 44 seconds were gone when the first settle request went out: 6 are left, not 45.
  assert.deepEqual(timeouts, [6000, 4000, 3000]);
  assert.deepEqual(h.sleeps, [2000, 3000]);
  assert.ok(h.clock.now - started <= 50_000, "the waits end inside the call's 50 seconds");
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");

  // With the 50 seconds already gone, one settle request is still made, with the least time a request is given.
  timeouts.length = 0;
  const slow = harness({
    verify: async () => {
      slow.clock.now += 55_000;
      return { isValid: true, payer: "Payer1111" };
    },
    settleBody: async (_body, timeoutMs) => {
      timeouts.push(timeoutMs);
      return SETTLED;
    },
  });
  assert.equal((await slow.handler({}, paid(token("pay-cb2")))).isError, undefined);
  assert.deepEqual(timeouts, [3000]);
  assert.deepEqual(slow.sleeps, []);
});

test("every offer of a payment says how a caller keeps its way back; an answer about an unresolved payment offers none", async () => {
  const h = harness({ settleBody: async () => PENDING });
  const offer = x402Error(await h.handler({}, {}));
  assert.ok(Array.isArray(offer.accepts));
  const hint = offer.resume as { meta: string; header: string; note: string };
  assert.equal(hint.meta, "x402/resume");
  assert.equal(hint.header, "X-PAYMENT-RESUME");
  assert.match(hint.note, /32 random bytes as base64url \(43 characters\), new for each payment/);
  assert.deepEqual(x402Error(await h.handler({}, paid("not-a-payment"))).resume, hint);
  const unresolved = x402Error(await h.handler({}, paid(token("pay-hint1"))));
  assert.equal(unresolved.error, SETTLEMENT_UNRESOLVED);
  assert.equal(unresolved.accepts, undefined);
  assert.equal(unresolved.resume, undefined);
});

test("classifySettle: only a definite answer is a failure", () => {
  const kind = (reply: SettleReply, first = true) => classifySettle(reply, first).kind;
  assert.equal(kind({ success: true, transaction: "t", network: "solana", httpStatus: 200 }), "settled");
  assert.equal(kind({ success: true, transaction: "t", network: "solana" }), "settled", "a reply without a status is HTTP 200");
  assert.equal(kind({ success: true, transaction: "t", network: "solana", httpStatus: 500 }), "unresolved");
  assert.equal(kind({ success: false, errorReason: "insufficient_funds", httpStatus: 200 }), "failed");
  assert.equal(kind({ success: false, errorReason: "insufficient_funds", httpStatus: 200 }, false), "failed");
  assert.equal(kind({ success: false, httpStatus: 200 }), "failed");
  assert.equal(classifySettle({ success: false, httpStatus: 200 }, true).kind === "failed" && (classifySettle({ success: false, httpStatus: 200 }, true) as { reason: string }).reason, "SETTLEMENT_FAILED");
  for (const errorReason of ["settlement_pending", "duplicate_settlement", "internal_server_error", "service_unavailable", "unexpected_settle_error", "settle_exact_svm_transaction_confirmation_timed_out", "idempotency_key_in_flight"] as const) {
    assert.equal(kind({ success: false, errorReason, httpStatus: 200 } as SettleReply), "unresolved", errorReason);
    assert.equal(kind({ success: false, errorReason, httpStatus: 400 } as SettleReply), "unresolved", `${errorReason} with HTTP 400`);
  }
  for (const httpStatus of [408, 409, 425, 429, 500, 502, 503, 504]) {
    assert.equal(kind({ success: false, errorReason: "insufficient_funds", httpStatus }), "unresolved", `HTTP ${httpStatus}`);
    assert.equal(kind({ httpStatus }), "unresolved", `HTTP ${httpStatus} without a readable body`);
  }
  for (const httpStatus of [400, 401, 403, 404, 422]) {
    assert.equal(kind({ success: false, errorReason: "invalid_payload", httpStatus }), "failed", `first request, HTTP ${httpStatus}`);
    assert.equal(kind({ httpStatus }), "failed", `first request, HTTP ${httpStatus} without a readable body`);
    assert.equal(kind({ success: false, errorReason: "invalid_payload", httpStatus }, false), "unresolved", `later request, HTTP ${httpStatus}`);
  }
  assert.equal(kind({ httpStatus: 200 }), "unresolved", "HTTP 200 without a readable body");
  assert.equal(kind({}), "unresolved");
  assert.equal(kind({ httpStatus: 302 }), "unresolved");
  const pending = classifySettle(PENDING, true);
  assert.deepEqual(pending, { kind: "unresolved", reason: "settlement_pending", transaction: SIGNATURE });
});

test("an unresolved payment presented five times in parallel runs the tool once", async () => {
  let reply: () => Promise<SettleReply> = async () => PENDING;
  const h = harness({ settleBody: async () => reply() });
  const tok = token("pay-u6");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  reply = async () => {
    await gate;
    return SETTLED;
  };
  const asked = h.events.filter((e) => e === "settle").length;
  const pending = Array.from({ length: 5 }, () => h.handler({}, resume(tok, first)));
  await new Promise((resolve) => setImmediate(resolve));
  release();
  const results = await Promise.all(pending);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  assert.equal(h.events.filter((e) => e === "settle").length, asked + 1);
  assert.equal(results.filter((r) => r.isError === undefined).length, 1);
  const waiting = results.filter((r) => errorCode(r) === SETTLEMENT_UNRESOLVED);
  assert.equal(waiting.length, 4);
  assert.match(String(x402Error(waiting[0]).message), /earlier call with this payment is still in progress/);
  assert.equal(x402Error(waiting[0]).accepts, undefined);
  assert.equal(waiting.some((r) => x402Error(r).resumeCode !== undefined), false, "a call told to wait is given no code");
});

test("a settlement whose call never answered cannot be resumed, even after ten minutes: nobody was given its resume code", async () => {
  const claimsDir = tempDir();
  const clock = { now: Date.now() };
  const events: string[] = [];
  let answerFirst: (reply: SettleReply) => void = () => {};
  const hung = new Promise<SettleReply>((resolve) => {
    answerFirst = resolve;
  });
  const first = harness({ claimsDir, clock, events, settle: () => hung });
  const tok = token("pay-u7c");
  const firstCall = first.handler({ x: "a" }, paid(tok));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(onlyClaim(claimsDir).s, "settling");
  const before = fs.readFileSync(path.join(claimsDir, claimFiles(claimsDir)[0]), "utf8");

  const second = harness({ claimsDir, clock, events, preflight: () => null });
  assert.match(String(x402Error(await second.handler({ x: "a" }, paid(tok))).message), /still in progress/);
  clock.now += 10 * 60 * 1000;
  // Someone who read the payment on chain and knows the call's arguments is exactly here.
  assertNotResumed(await second.handler({ x: "a" }, paid(tok)));
  assertNotResumed(await second.handler({ x: "a" }, resume(tok, WRONG_CODE)));
  assertNotResumed(await second.handler({ x: "a" }, resume(tok, "short")));
  assert.equal(events.filter((e) => e === "settle").length, 1, "the facilitator is not asked");
  assert.equal(events.filter((e) => e === "preflight").length, 0, "the readiness check is not set off");
  assert.equal(events.filter((e) => e === "tool").length, 0);
  assert.equal(fs.readFileSync(path.join(claimsDir, claimFiles(claimsDir)[0]), "utf8"), before, "the claim is untouched");
  // Refused resumes are logged once per claim and reason in ten minutes, however many calls there are.
  const refusedLogs = (why: string) => second.logs.filter((l) => l.includes(`an unresolved settlement was not resumed: ${why}`)).length;
  assert.equal(refusedLogs("no resume code"), 1, "a missing and a misshapen code are one reason");
  assert.equal(refusedLogs("wrong resume code"), 1);
  for (let i = 0; i < 50; i++) assertNotResumed(await second.handler({ x: "a" }, resume(tok, WRONG_CODE)));
  assert.equal(refusedLogs("wrong resume code"), 1);
  clock.now += 10 * 60 * 1000;
  assertNotResumed(await second.handler({ x: "a" }, paid(tok)));
  assert.equal(refusedLogs("no resume code"), 2);
  assert.equal(events.filter((e) => e === "settle").length, 1);
  assert.equal(fs.readFileSync(path.join(claimsDir, claimFiles(claimsDir)[0]), "utf8"), before);

  // The call that owns the settlement is still the only one that can finish it.
  answerFirst({ success: true, transaction: "sig-own", network: "solana", payer: "Payer1111" });
  assert.equal((await firstCall).isError, undefined);
  assert.equal(events.filter((e) => e === "tool").length, 1);
  assert.equal(onlyClaim(claimsDir).s, "settled");
});

test("a settlement recorded before resume codes whose call is gone is resumed after ten minutes, and the call that comes back late does not run the tool again", async () => {
  const claimsDir = tempDir();
  const clock = { now: Date.now() };
  const events: string[] = [];
  let answerFirst: (reply: SettleReply) => void = () => {};
  const hung = new Promise<SettleReply>((resolve) => {
    answerFirst = resolve;
  });
  const first = harness({ claimsDir, clock, events, settle: () => hung });
  const tok = token("pay-u7");
  const firstCall = first.handler({ x: "a" }, paid(tok));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(onlyClaim(claimsDir).s, "settling");
  dropResumeHash(claimsDir);

  // While the first call may still be at work, the payment is neither used up nor resumable.
  const second = harness({ claimsDir, clock, events });
  const early = await second.handler({ x: "a" }, paid(tok));
  assert.equal(errorCode(early), SETTLEMENT_UNRESOLVED);
  assert.equal(x402Error(early).accepts, undefined);
  clock.now += 10 * 60 * 1000 - 1;
  assert.equal(errorCode(await second.handler({ x: "a" }, paid(tok))), SETTLEMENT_UNRESOLVED);
  assert.equal(events.filter((e) => e === "tool").length, 0);
  assert.equal(events.filter((e) => e === "settle").length, 1);

  clock.now += 1;
  const late = await second.handler({ x: "a" }, paid(tok));
  assert.equal(late.isError, undefined);
  assert.equal(events.filter((e) => e === "tool").length, 1);
  assert.equal(onlyClaim(claimsDir).s, "settled");

  answerFirst({ success: true, transaction: "sig-late", network: "solana", payer: "Payer1111" });
  const stale = await firstCall;
  assert.equal(errorCode(stale), SETTLEMENT_UNRESOLVED);
  assert.equal(stale._meta?.["x402/payment-response"], undefined);
  assert.equal(events.filter((e) => e === "tool").length, 1, "one payment, one tool run");
  assert.ok(first.logs.some((l) => l.includes("this call no longer owns the settlement")));
  assert.equal(onlyClaim(claimsDir).tx, "sig-1", "the record is the later call's");
});

test("a call that comes back late with a refusal, after a later call took its settlement over, releases nothing and offers nothing", async () => {
  const claimsDir = tempDir();
  const clock = { now: Date.now() };
  let answerFirst: (reply: SettleReply) => void = () => {};
  const hung = new Promise<SettleReply>((resolve) => {
    answerFirst = resolve;
  });
  const first = harness({ claimsDir, clock, settle: () => hung });
  const tok = token("pay-u7b");
  const firstCall = first.handler({}, paid(tok));
  await new Promise((resolve) => setImmediate(resolve));
  // A record as the version before resume codes wrote it. It asks for no code and is given none: whoever resumed it
  // first would otherwise hold the only code, and lock out the caller the payment belongs to.
  dropResumeHash(claimsDir);
  clock.now += 10 * 60 * 1000;
  const second = harness({ claimsDir, clock, settleBody: async () => PENDING });
  const taken = await second.handler({}, paid(tok));
  assert.equal(errorCode(taken), SETTLEMENT_UNRESOLVED);
  assert.equal(x402Error(taken).resumeCode, undefined);
  assert.doesNotMatch(String(x402Error(taken).message), /resume code/);
  assert.match(String(x402Error(taken).message), /Present the same payment with the same call again to get the result/);
  assert.equal(onlyClaim(claimsDir).s, "unresolved");
  assert.equal(onlyClaim(claimsDir).rc, undefined, "the record stays as the earlier version wrote it");
  const asked = second.events.filter((e) => e === "settle").length;
  assert.equal(errorCode(await second.handler({}, paid(tok))), SETTLEMENT_UNRESOLVED);
  assert.ok(second.events.filter((e) => e === "settle").length > asked, "the same call resumes it again, as before resume codes");
  assert.equal(onlyClaim(claimsDir).rc, undefined);
  answerFirst({ success: false, errorReason: "insufficient_funds", transaction: "", network: "solana" });
  const stale = await firstCall;
  assert.equal(errorCode(stale), SETTLEMENT_UNRESOLVED);
  assert.equal(x402Error(stale).accepts, undefined);
  assert.equal(onlyClaim(claimsDir).s, "unresolved", "the claim is the later call's to end");
});

test("a claim's lock that stays taken does not stop the owner recording the outcome: the tool runs once, and not again later", async () => {
  let lock = "";
  const h = harness({
    settleBody: async () => {
      // Another process takes this claim's lock while the settle request is out, and never lets go.
      fs.writeFileSync(lock, "someone else");
      const fresh = new Date(h.clock.now);
      fs.utimesSync(lock, fresh, fresh);
      return SETTLED;
    },
  });
  const tok = token("pay-u13");
  lock = path.join(h.claimsDir, `${paymentClaimKey(decodePayment(tok))}.lock`);
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  assert.equal(h.sleeps.length, 20, "it waited for the lock first");
  assert.ok(h.logs.some((l) => l.includes("lock stayed taken")));
  assert.equal(onlyClaim(h.claimsDir).s, "settled");
  assert.equal(fs.readFileSync(lock, "utf8"), "someone else", "a lock that is not its own is left alone");
  fs.rmSync(lock);
  h.clock.now += 11 * 60 * 1000;
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("a settlement is resumed only inside 23 hours of its first request: the facilitator forgets after 24", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-u14");
  const unresolved = await h.handler({}, paid(tok));
  assert.equal(errorCode(unresolved), SETTLEMENT_UNRESOLVED);
  const first = Number(onlyClaim(h.claimsDir).f);
  // Asking again later rewrites the record, and keeps the time of the first request.
  h.clock.now += 22 * 60 * 60 * 1000;
  assert.equal(errorCode(await h.handler({}, resume(tok, unresolved))), SETTLEMENT_UNRESOLVED);
  assert.equal(onlyClaim(h.claimsDir).f, first);
  assert.ok(Number(onlyClaim(h.claimsDir).t) > first);
  // Past 23 hours the facilitator is not asked: a failure it reported now would not be this payment's outcome.
  h.clock.now = first + 23 * 60 * 60 * 1000;
  reply = { success: false, errorReason: "invalid_transaction_state", transaction: "", network: "solana", payer: "", httpStatus: 200 };
  const asked = h.events.filter((e) => e === "settle").length;
  assert.equal(errorCode(await h.handler({}, resume(tok, unresolved))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "settle").length, asked);
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
});

test("a settle request too long to record is not sent: the payment is refused unpaid", async () => {
  const h = harness({ description: "d".repeat(16 * 1024) });
  const tok = token("pay-u15");
  const result = await h.handler({}, paid(tok));
  assert.equal(errorCode(result), "PAYMENT_CLAIM_UNAVAILABLE");
  assert.equal(x402Error(result).accepts, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify"]);
  assert.deepEqual(claimFiles(h.claimsDir), []);
  assert.ok(h.logs.some((l) => l.includes("settle request too long to record")));
});

test("a refusal after a request that provably never reached the facilitator is still a first answer; after any other failure it is not", async () => {
  const refusal: SettleReply = { success: false, errorReason: "free_tier_exhausted", transaction: "", network: "solana", payer: "", httpStatus: 403 };
  const failingWith = (cause: unknown) => {
    let attempt = 0;
    return async (): Promise<SettleReply> => {
      if (++attempt === 1) throw new TypeError("fetch failed", { cause });
      return refusal;
    };
  };
  for (const code of ["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT"]) {
    const h = harness({ settleBody: failingWith(Object.assign(new Error("connect failed"), { code })) });
    const refused = await h.handler({}, paid(token(`pay-u16-${code}`)));
    assert.equal(errorCode(refused), "free_tier_exhausted", code);
    assert.ok(Array.isArray(x402Error(refused).accepts), code);
    assert.deepEqual(claimFiles(h.claimsDir), [], code);
  }
  for (const cause of [Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }), Object.assign(new Error("aborted"), { code: "UND_ERR_SOCKET" }), undefined]) {
    const h = harness({ settleBody: failingWith(cause) });
    assert.equal(errorCode(await h.handler({}, paid(token(`pay-u16-${String((cause as { code?: string } | undefined)?.code)}`)))), SETTLEMENT_UNRESOLVED);
    assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
  }
});

test("locks and half-written records left by a dead process are cleared with the old claims", async () => {
  const h = harness();
  assert.equal((await h.handler({}, paid(token("pay-u17a")))).isError, undefined);
  const stale = ["abc.lock", "abc.claim.1234.tmp"].map((name) => path.join(h.claimsDir, name));
  const recent = ["def.lock", "def.claim.5678.tmp"].map((name) => path.join(h.claimsDir, name));
  h.clock.now += 10 * 60 * 1000;
  for (const file of [...stale, ...recent]) fs.writeFileSync(file, "");
  const old = new Date(h.clock.now - 61 * 1000);
  for (const file of stale) fs.utimesSync(file, old, old);
  const now = new Date(h.clock.now);
  for (const file of recent) fs.utimesSync(file, now, now);
  assert.equal((await h.handler({}, paid(token("pay-u17b")))).isError, undefined);
  for (const file of stale) assert.equal(fs.existsSync(file), false, file);
  for (const file of recent) assert.equal(fs.existsSync(file), true, file);
  assert.equal(claimFiles(h.claimsDir).length, 2);
  // An old lock whose claim is still there is left for the call that next needs it.
  const beside = path.join(h.claimsDir, claimFiles(h.claimsDir)[0].replace(/\.claim$/, ".lock"));
  fs.writeFileSync(beside, "");
  h.clock.now += 10 * 60 * 1000;
  const older = new Date(h.clock.now - 61 * 1000);
  fs.utimesSync(beside, older, older);
  assert.equal((await h.handler({}, paid(token("pay-u17c")))).isError, undefined);
  assert.equal(fs.existsSync(beside), true);
});

test("on resuming, the readiness check comes first: a tool that is not ready leaves the settlement as it is", async () => {
  let reply = PENDING;
  let ready: string | null = null;
  const h = harness({ settleBody: async () => reply, preflight: () => ready });
  const tok = token("pay-u8");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  const asked = h.events.filter((e) => e === "settle").length;
  reply = SETTLED;
  ready = "The browser is not available right now. No payment was taken. Try again later.";
  // Without the resume code the check is not even set off.
  const checksBefore = h.events.filter((e) => e === "preflight").length;
  assertNotResumed(await h.handler({}, paid(tok)));
  assert.equal(h.events.filter((e) => e === "preflight").length, checksBefore);
  const notReady = await h.handler({}, resume(tok, first));
  assert.equal(errorCode(notReady), SETTLEMENT_UNRESOLVED);
  assert.match(String(x402Error(notReady).message), /not ready to run this call yet/);
  assert.doesNotMatch(JSON.stringify(notReady), /No payment was taken/, "the payment may have been taken: the tool's own refusal text is not passed on");
  assert.equal(h.events.filter((e) => e === "settle").length, asked, "the facilitator is not asked");
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
  ready = null;
  assert.equal((await h.handler({}, resume(tok, first))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  // A payment that is used up, or someone else's call, never sets the check off.
  const checks = h.events.filter((e) => e === "preflight").length;
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(errorCode(await h.handler({ x: "other" }, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "preflight").length, checks);
});

test("a lock left by a process that died is cleared; a fresh one makes the caller wait", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-u9");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  reply = SETTLED;
  const asked = h.events.filter((e) => e === "settle").length;
  const lock = path.join(h.claimsDir, `${paymentClaimKey(decodePayment(tok))}.lock`);
  fs.writeFileSync(lock, "");
  const fresh = new Date(h.clock.now);
  fs.utimesSync(lock, fresh, fresh);
  const held = await h.handler({}, resume(tok, first));
  assert.equal(errorCode(held), SETTLEMENT_UNRESOLVED);
  assert.match(String(x402Error(held).message), /earlier call with this payment is still in progress/);
  assert.equal(h.events.filter((e) => e === "settle").length, asked);
  const old = new Date(h.clock.now - 60 * 1000 - 1000);
  fs.utimesSync(lock, old, old);
  assert.equal((await h.handler({}, resume(tok, first))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  assert.deepEqual(leftovers(h.claimsDir), []);
});

test("a claim record this code cannot read, or one that names an oversized request, is a used payment", async () => {
  const h = harness();
  const tok = token("pay-u10");
  const file = path.join(h.claimsDir, `${paymentClaimKey(decodePayment(tok))}.claim`);
  const call = paidCallId("echo", {});
  for (const record of [
    "not json",
    "{}",
    JSON.stringify({ s: "unresolved", t: 1 }),
    JSON.stringify({ s: "unresolved", t: 1, call, body: "x".repeat(16 * 1024 + 1) }),
    JSON.stringify({ s: "settling", t: 1, call, body: "{}" }),
    JSON.stringify({ s: "elsewhere", t: 1, call, body: "{}" }),
    JSON.stringify({ s: "pending", t: 1 }),
    JSON.stringify({ s: "settled", t: 1, tx: "sig" }),
  ]) {
    fs.writeFileSync(file, record);
    assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED", record.slice(0, 40));
  }
  assert.deepEqual(paymentEvents(h.events), []);
});

test("an unresolved settlement names a transaction to its caller only when it looks like one", async () => {
  const h = harness({
    settleBody: async () => ({ success: false, errorReason: "settlement_pending", transaction: "<b>see http://example.test</b>", httpStatus: 200 }) as SettleReply,
  });
  const result = await h.handler({}, paid(token("pay-u11")));
  assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
  assert.equal(x402Error(result).transaction, undefined);
  assert.equal(onlyClaim(h.claimsDir).tx, undefined);
});

test("the number of settle requests one call makes is bounded even when the clock does not move", async () => {
  const h = harness({ settleBody: async () => PENDING, stoppedClock: true });
  assert.equal(errorCode(await h.handler({}, paid(token("pay-u12")))), SETTLEMENT_UNRESOLVED);
  assert.equal(h.events.filter((e) => e === "settle").length, 12);
});

test("postSettle sends the body as given and returns the reply with its status, whatever the status", async () => {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const answering = (status: number, text: string): typeof fetch =>
    (async (url: unknown, init?: RequestInit) => {
      seen.push({ url: String(url), init: init ?? {} });
      return new Response(text, { status, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
  const body = '{"x402Version":1,"paymentPayload":{"b":1,"a":2},"paymentRequirements":{}}';
  assert.deepEqual(await postSettle("https://facilitator.example", body, 5000, answering(200, '{"success":true,"transaction":"t","network":"solana"}')), {
    success: true,
    transaction: "t",
    network: "solana",
    httpStatus: 200,
  });
  assert.equal(seen[0].url, "https://facilitator.example/settle");
  assert.equal(seen[0].init.method, "POST");
  assert.equal(seen[0].init.body, body);
  assert.ok(seen[0].init.signal instanceof AbortSignal, "the request has a time limit");
  assert.deepEqual(await postSettle("https://facilitator.example", body, 5000, answering(409, '{"success":false,"errorReason":"duplicate_settlement","transaction":""}')), {
    success: false,
    errorReason: "duplicate_settlement",
    transaction: "",
    httpStatus: 409,
  });
  assert.deepEqual(await postSettle("https://facilitator.example", body, 5000, answering(502, "<html>Bad Gateway</html>")), { httpStatus: 502 });
  assert.deepEqual(await postSettle("https://facilitator.example", body, 5000, answering(200, '{"success":true,"httpStatus":500}')), { success: true, httpStatus: 200 });
  assert.deepEqual(await postSettle("https://facilitator.example", body, 5000, answering(200, "[1]")), { httpStatus: 200 });
  const refusing = (async () => {
    throw new TypeError("fetch failed");
  }) as typeof fetch;
  await assert.rejects(postSettle("https://facilitator.example", body, 5000, refusing), /fetch failed/);
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
  assert.equal(h.events.filter((e) => e === "verify").length, 1);
  // The four copies are the same call with the same payment, which may yet be taken: they are told to wait, and
  // are not offered a second payment.
  const waiting = results.filter((r) => errorCode(r) === SETTLEMENT_UNRESOLVED);
  assert.equal(waiting.length, 4);
  for (const copy of waiting) {
    assert.equal(x402Error(copy).accepts, undefined);
    assert.match(String(x402Error(copy).message), /earlier call with this payment is still in progress/);
  }
  // Once the first call is done the payment is used up, for the same call too.
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
});

test("the same payment with a different call while the first is in flight is refused as used, as is a claim that never got as far as a settle request", async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const h = harness({
    verify: async () => {
      await gate;
      return { isValid: true, payer: "Payer1111" };
    },
  });
  const tok = token("pay-5b");
  const first = h.handler({ x: "a" }, paid(tok));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(onlyClaim(h.claimsDir).s, "pending");
  assert.equal(onlyClaim(h.claimsDir).call, paidCallId("echo", { x: "a" }));
  assert.equal(errorCode(await h.handler({ x: "b" }, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(errorCode(await h.handler({ x: "a" }, paid(tok))), SETTLEMENT_UNRESOLVED);
  // Ten minutes on and still "pending": its process died before anything was sent. Nothing can be taken, so the
  // payer is not told to wait.
  h.clock.now += 10 * 60 * 1000;
  assert.equal(errorCode(await h.handler({ x: "a" }, paid(tok))), "PAYMENT_ALREADY_USED");
  h.clock.now -= 10 * 60 * 1000;
  release();
  assert.equal((await first).isError, undefined);
  // A "pending" record of the previous version of this file names no call: used, as it always was.
  const older = token("pay-5c");
  fs.writeFileSync(path.join(h.claimsDir, `${paymentClaimKey(decodePayment(older))}.claim`), JSON.stringify({ s: "pending", t: h.clock.now }));
  assert.equal(errorCode(await h.handler({ x: "a" }, paid(older))), "PAYMENT_ALREADY_USED");
});

test("one payment sent to two servers sharing the claim directory runs one tool", async () => {
  const claimsDir = tempDir();
  const events: string[] = [];
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const settle = async (): Promise<SettleReply> => {
    await gate;
    return { success: true, transaction: "sig-6", network: "solana", payer: "Payer1111" };
  };
  const serverA = harness({ claimsDir, events, settle });
  const serverB = harness({ claimsDir, events, settle, toolName: "echo-b" });
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
  assert.equal(x402Error(result).accepts, undefined, "a service that cannot record payments does not ask for one");
  assert.deepEqual(paymentEvents(h.events), []);
  assert.ok(h.logs.some((l) => l.includes("claim store unavailable")));
});

/** Runs `body` with one function of node:fs replaced (the module under test uses the same object), then puts it back. */
async function withFs<K extends "readFileSync" | "openSync" | "renameSync">(name: K, replacement: (original: (typeof fs)[K]) => (typeof fs)[K], body: () => Promise<void>): Promise<void> {
  const original = fs[name];
  fs[name] = replacement(original);
  try {
    await body();
  } finally {
    fs[name] = original;
  }
}
const fsError = (code: string) => Object.assign(new Error(`${code}: simulated`), { code });

test("a claim that cannot be read, or a claim directory that fails, never leads to an offer of a new payment", async () => {
  let reply = PENDING;
  const h = harness({ settleBody: async () => reply });
  const tok = token("pay-u18");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  reply = SETTLED;
  const asked = h.events.filter((e) => e === "settle").length;

  // The claim file is there, and reading it fails (out of file handles): the claim may say "unresolved".
  await withFs(
    "readFileSync",
    (original) => ((file: unknown, ...rest: unknown[]) => {
      if (String(file).endsWith(".claim")) throw fsError("EMFILE");
      return (original as (...args: unknown[]) => unknown)(file, ...rest);
    }) as typeof fs.readFileSync,
    async () => {
      const result = await h.handler({}, resume(tok, first));
      assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
      assert.equal(x402Error(result).accepts, undefined);
      assert.match(String(x402Error(result).message), /cannot read this payment's record right now/);
    },
  );
  assert.ok(h.logs.some((l) => l.includes("could not read a payment claim") && l.includes("EMFILE")));

  // Taking the claim fails with something other than "it exists".
  await withFs(
    "openSync",
    (original) => ((file: unknown, ...rest: unknown[]) => {
      if (String(file).endsWith(".claim")) throw fsError("EMFILE");
      return (original as (...args: unknown[]) => unknown)(file, ...rest);
    }) as typeof fs.openSync,
    async () => {
      const result = await h.handler({}, resume(tok, first));
      assert.equal(errorCode(result), "PAYMENT_CLAIM_UNAVAILABLE");
      assert.equal(x402Error(result).accepts, undefined);
    },
  );
  assert.equal(h.events.filter((e) => e === "settle").length, asked, "the facilitator was not asked meanwhile");
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
  // With the directory working again the same call resumes it.
  assert.equal((await h.handler({}, resume(tok, first))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("a payment that settled but could not be recorded as settled does not run the tool until a call can record it", async () => {
  // Every write to the claim fails once the settle request is out.
  let failing = false;
  const h = harness({
    settleBody: async () => {
      failing = true;
      return SETTLED;
    },
  });
  const tok = token("pay-u19");
  let code = "";
  await withFs(
    "renameSync",
    (original) => ((from: fs.PathLike, to: fs.PathLike) => {
      if (failing && String(to).endsWith(".claim")) throw fsError("ENOSPC");
      return original(from, to);
    }) as typeof fs.renameSync,
    async () => {
      const result = await h.handler({}, paid(tok));
      assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
      assert.match(String(x402Error(result).message), /settled, but the call could not be recorded as paid/);
      assert.equal(x402Error(result).accepts, undefined);
      assert.equal(x402Error(result).retryAfterSeconds, 600, "the claim stays this call's for ten minutes");
      assert.equal(x402Error(result).transaction, SIGNATURE);
      code = resumeCodeOf(result);
    },
  );
  assert.equal(h.events.includes("tool"), false);
  assert.ok(h.logs.some((l) => l.includes("settled (paid), but the claim could not be marked settled, tool not run")));
  assert.equal(onlyClaim(h.claimsDir).s, "settling");
  assert.deepEqual(leftovers(h.claimsDir), []);
  failing = false;
  assert.match(String(x402Error(await h.handler({}, paid(tok))).message), /still in progress/);
  h.clock.now += 10 * 60 * 1000;
  assertNotResumed(await h.handler({}, paid(tok)));
  assert.equal(h.events.includes("tool"), false);
  assert.equal((await h.handler({}, resume(tok, code))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  assert.equal(onlyClaim(h.claimsDir).s, "settled");
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("when only the settled record fails to write, the claim is handed on as unresolved and the same call can resume at once", async () => {
  let failures = 0;
  const h = harness({
    settleBody: async () => {
      if (failures === 0) failures = 1;
      return SETTLED;
    },
  });
  const tok = token("pay-u20");
  await withFs(
    "renameSync",
    (original) => ((from: fs.PathLike, to: fs.PathLike) => {
      if (failures === 1 && String(to).endsWith(".claim")) {
        failures = 2;
        throw fsError("EIO");
      }
      return original(from, to);
    }) as typeof fs.renameSync,
    async () => {
      const result = await h.handler({}, paid(tok));
      assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
      assert.match(String(x402Error(result).message), /could not be recorded as paid/);
      assert.equal(x402Error(result).retryAfterSeconds, 30);
      assert.equal(h.events.includes("tool"), false);
      assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
      assert.deepEqual(onlyClaim(h.claimsDir).paid, { tx: SIGNATURE, network: "solana" }, "the record says the payment is settled");
      // Other arguments do not get the paid call.
      assert.equal(errorCode(await h.handler({ x: "other" }, paid(tok))), "PAYMENT_ALREADY_USED");
      // A payment known to be settled is the one most worth taking: without the code the call is not run.
      assertNotResumed(await h.handler({}, paid(tok)));
      assertNotResumed(await h.handler({}, resume(tok, WRONG_CODE)));
      assert.equal(h.events.includes("tool"), false);
      const resumed = await h.handler({}, resume(tok, result));
      assert.equal(resumed.isError, undefined);
      assert.equal((resumed._meta?.["x402/payment-response"] as X402Settlement).transaction, SIGNATURE);
    },
  );
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
  assert.equal(h.events.filter((e) => e === "settle").length, 1, "the facilitator already answered: it is not asked again");
  assert.ok(h.logs.some((l) => l.includes("resuming a settled payment whose call has not run")));
  assert.equal(onlyClaim(h.claimsDir).s, "settled");
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
});

test("an owner that cannot read its own claim when the answer comes does not run the tool, and releases nothing it cannot see", async () => {
  let unreadable = false;
  const h = harness({
    settleBody: async () => {
      unreadable = true;
      return SETTLED;
    },
  });
  const tok = token("pay-u23");
  let code = "";
  await withFs(
    "readFileSync",
    (original) => ((file: unknown, ...rest: unknown[]) => {
      if (unreadable && String(file).endsWith(".claim")) throw fsError("EIO");
      return (original as (...args: unknown[]) => unknown)(file, ...rest);
    }) as typeof fs.readFileSync,
    async () => {
      const result = await h.handler({}, paid(tok));
      assert.equal(errorCode(result), SETTLEMENT_UNRESOLVED);
      assert.match(String(x402Error(result).message), /could not be recorded as paid/);
      assert.equal(x402Error(result).retryAfterSeconds, 600);
      assert.equal(x402Error(result).accepts, undefined);
      code = resumeCodeOf(result);
    },
  );
  assert.equal(h.events.includes("tool"), false);
  assert.equal(onlyClaim(h.claimsDir).s, "settling", "the claim is still held");
  assert.deepEqual(leftovers(h.claimsDir), []);
  unreadable = false;
  h.clock.now += 10 * 60 * 1000;
  assert.equal((await h.handler({}, resume(tok, code))).isError, undefined);
  assert.equal(h.events.filter((e) => e === "tool").length, 1);
});

test("resuming gets 20 seconds, and a readiness check that throws leaves the settlement as it is", async () => {
  const timeouts: number[] = [];
  let ready: () => string | null = () => null;
  const h = harness({
    settleBody: async (_body, timeoutMs) => {
      timeouts.push(timeoutMs);
      return PENDING;
    },
    preflight: () => ready(),
  });
  const tok = token("pay-u21");
  const first = await h.handler({}, paid(tok));
  assert.equal(errorCode(first), SETTLEMENT_UNRESOLVED);
  timeouts.length = 0;
  h.sleeps.length = 0;
  const second = await h.handler({}, resume(tok, first));
  assert.equal(errorCode(second), SETTLEMENT_UNRESOLVED);
  assert.equal(resumeCodeOf(second), resumeCodeOf(first), "one code for the life of the claim: a lost answer does not strand the caller");
  assert.equal(onlyClaim(h.claimsDir).rc, sha256hex(resumeCodeOf(first)));
  assert.deepEqual(h.sleeps, [2000, 3000, 5000]);
  assert.deepEqual(timeouts, [20000, 18000, 15000, 10000]);
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");

  timeouts.length = 0;
  ready = () => {
    throw new Error("browser exploded at C:\\secret\\path");
  };
  const refused = await h.handler({}, resume(tok, first));
  assert.equal(errorCode(refused), SETTLEMENT_UNRESOLVED);
  assert.match(String(x402Error(refused).message), /not ready to run this call yet/);
  assert.doesNotMatch(JSON.stringify(refused), /exploded|secret/, "the cause stays in the log");
  assert.ok(h.logs.some((l) => l.includes("preflight check threw, unresolved settlement left as it is") && l.includes("exploded")));
  assert.deepEqual(timeouts, [], "the facilitator is not asked");
  assert.equal(onlyClaim(h.claimsDir).s, "unresolved");
});

test("a call none of whose settle requests ever connected has sent nothing: that is a failure, not an open outcome", async () => {
  const refusedConnection = async (): Promise<SettleReply> => {
    throw new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { code: "ECONNREFUSED" }) });
  };
  const h = harness({ settleBody: refusedConnection });
  const tok = token("pay-u22");
  const failed = await h.handler({}, paid(tok));
  assert.equal(errorCode(failed), "SETTLEMENT_FAILED");
  assert.ok(Array.isArray(x402Error(failed).accepts), "nothing was sent, so a new payment may be offered");
  assert.equal(h.events.filter((e) => e === "settle").length, 7, "it kept trying for the whole 45 seconds first");
  assert.deepEqual(claimFiles(h.claimsDir), []);
  assert.ok(h.logs.some((l) => l.includes("settle failed, tool not run: reason=SETTLEMENT_FAILED (no reply") && l.includes("fetch failed")));

  // Once any request may have arrived, the same silence leaves the outcome open.
  let attempt = 0;
  const later = harness({
    settleBody: async () => {
      if (++attempt === 1) throw new TypeError("fetch failed", { cause: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) });
      return refusedConnection();
    },
  });
  const laterToken = token("pay-u22b");
  const unresolved = await later.handler({}, paid(laterToken));
  assert.equal(errorCode(unresolved), SETTLEMENT_UNRESOLVED);
  assert.equal(onlyClaim(later.claimsDir).s, "unresolved");
  // And on a resume, silence never releases: an earlier call already sent the request.
  attempt = 1;
  const asked = later.events.filter((e) => e === "settle").length;
  const resumed = await later.handler({}, resume(laterToken, unresolved));
  assert.equal(errorCode(resumed), SETTLEMENT_UNRESOLVED);
  assert.equal(x402Error(resumed).accepts, undefined);
  assert.match(String(x402Error(resumed).message), /sent for settlement and the outcome is not known yet/);
  assert.ok(later.events.filter((e) => e === "settle").length > asked, "the resume asked the facilitator, and none of its requests connected");
  assert.equal(onlyClaim(later.claimsDir).s, "unresolved");
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

test("a preflight refusal comes after verify and before settle: nothing is taken, the tool does not run, and the payment can be used later", async () => {
  let ready = false;
  const h = harness({ preflight: () => (ready ? null : "Browser unavailable. No payment was taken. Try again later.") });
  const tok = token("pay-15");
  const refused = await h.handler({}, paid(tok));
  assert.equal(refused.isError, true);
  assert.equal(refused.content[0].text, "Error: Browser unavailable. No payment was taken. Try again later.");
  assert.equal(refused._meta, undefined, "no payment response and no payment request ride on the refusal");
  assert.deepEqual(paymentEvents(h.events), ["verify", "preflight"]);
  assert.ok(h.logs.some((l) => l.includes("not ready, payment not settled, tool not run")));
  // The claim was released: the same payment goes through once the dependency is back.
  ready = true;
  const second = await h.handler({}, paid(tok));
  assert.equal(second.isError, undefined);
  assert.deepEqual(paymentEvents(h.events), ["verify", "preflight", "verify", "preflight", "settle", "tool"]);
  // And having settled, it cannot be used again.
  assert.equal(errorCode(await h.handler({}, paid(tok))), "PAYMENT_ALREADY_USED");
});

test("the preflight never runs for a call without a payment, or with one that does not verify", async () => {
  const h = harness({ preflight: () => "not ready", verify: async () => ({ isValid: false, invalidReason: "insufficient_funds", payer: "Payer1111" }) });
  assert.equal(errorCode(await h.handler({}, {})), "PAYMENT_REQUIRED");
  assert.equal(errorCode(await h.handler({}, paid("not-a-payment"))), "INVALID_PAYMENT");
  assert.equal(errorCode(await h.handler({}, paid(token("pay-16")))), "insufficient_funds");
  assert.deepEqual(paymentEvents(h.events), ["verify"], "only a verified payment sets the readiness check off");
});

test("a preflight that throws refuses the call the same way: nothing settled, claim released, cause in the log only", async () => {
  let broken = true;
  const h = harness({
    preflight: () => {
      if (broken) throw new Error("launcher exploded at /opt/secret/path");
      return null;
    },
  });
  const tok = token("pay-17");
  const refused = await h.handler({}, paid(tok));
  assert.equal(refused.isError, true);
  assert.equal(refused.content[0].text, `Error: ${PREFLIGHT_FAILED}`);
  assert.ok(!JSON.stringify(refused).includes("/opt/secret"), "the cause does not reach the caller");
  assert.ok(h.logs.some((l) => l.includes("preflight check threw") && l.includes("/opt/secret/path")));
  assert.deepEqual(paymentEvents(h.events), ["verify", "preflight"]);
  broken = false;
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
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

const authorityOf = (tx: string) =>
  paymentAuthority({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: tx } });

test("the payer is the token transfer's authority, and differs per paying wallet", async () => {
  assert.equal(authorityOf(txBase64("a", 0, { payer: "wallet-a" })), walletOf("wallet-a"));
  assert.equal(authorityOf(txBase64("b", 0, { payer: "wallet-b" })), walletOf("wallet-b"));
  const h = harness();
  await h.handler({}, paid(token("pay-15", 0, { payer: "wallet-a" })));
  await h.handler({}, paid(token("pay-16", 0, { payer: "wallet-b" })));
  const payers = h.extras.map((e) => (e as { x402Settlement: X402Settlement }).x402Settlement.payer);
  assert.deepEqual(payers, [walletOf("wallet-a"), walletOf("wallet-b")]);
});

test("a payment without exactly one token transfer signed by its authority is refused unpaid", async () => {
  const h = harness();
  for (const shape of [{ transfers: 0 }, { transfers: 2 }, { authorityIsSigner: false }, { program: key32("not-a-token-program") }]) {
    assert.equal(authorityOf(txBase64("x", 0, shape)), null, JSON.stringify(shape));
    assert.equal(errorCode(await h.handler({}, paid(token(`pay-17-${JSON.stringify(shape)}`, 0, shape)))), "INVALID_PAYMENT");
  }
  assert.deepEqual(paymentEvents(h.events), []);
});

test("a payment built with @solana/kit the way x402's client builds it yields the client's wallet", async () => {
  const client = await generateKeyPairSigner();
  const feePayer = (await generateKeyPairSigner()).address;
  const source = (await generateKeyPairSigner()).address;
  const destination = (await generateKeyPairSigner()).address;
  const recentBlockhash = blockhash((await generateKeyPairSigner()).address);
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(feePayer, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: recentBlockhash, lastValidBlockHeight: 1000n }, tx),
    (tx) =>
      appendTransactionMessageInstructions(
        [
          getSetComputeUnitLimitInstruction({ units: 8000 }),
          getSetComputeUnitPriceInstruction({ microLamports: 1 }),
          getTransferCheckedInstruction(
            {
              source,
              mint: address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
              destination,
              authority: client,
              amount: 5000n,
              decimals: 6,
            },
            { programAddress: TOKEN_PROGRAM_ADDRESS },
          ),
        ],
        tx,
      ),
  );
  const wire = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(message));
  const tok = encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: wire } });
  assert.equal(paymentAuthority(decodePayment(tok)), client.address);
  assert.notEqual(paymentAuthority(decodePayment(tok)), feePayer);
  const h = harness();
  assert.equal((await h.handler({}, paid(tok))).isError, undefined);
  assert.equal((h.extras[0] as { x402Settlement: X402Settlement }).x402Settlement.payer, client.address);
});

test("a transfer authorized by the fee payer is refused unpaid", async () => {
  const h = harness();
  // The fee payer slot (account 0) as authority, e.g. after the attacker approves it as delegate.
  assert.equal(authorityOf(txBase64("y", 0, { authorityIndex: 0 })), null);
  assert.equal(errorCode(await h.handler({}, paid(token("pay-18", 0, { authorityIndex: 0 })))), "INVALID_PAYMENT");
  // The facilitator's published fee payer as authority at a later signer index.
  const sneaky = { payer: "fee-payer", feePayerSeed: "attacker-fee-payer" };
  assert.equal(authorityOf(txBase64("z", 0, sneaky)), walletOf("fee-payer"));
  assert.equal(errorCode(await h.handler({}, paid(token("pay-19", 0, sneaky)))), "INVALID_PAYMENT");
  assert.deepEqual(paymentEvents(h.events), []);
});

test("a Token-2022 payment with a create-ATA instruction, built with @solana/kit, yields the client's wallet", async () => {
  const client = await generateKeyPairSigner();
  const feePayer = (await generateKeyPairSigner()).address;
  const source = (await generateKeyPairSigner()).address;
  const destination = (await generateKeyPairSigner()).address;
  const owner = (await generateKeyPairSigner()).address;
  const mint = (await generateKeyPairSigner()).address;
  const recentBlockhash = blockhash((await generateKeyPairSigner()).address);
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(feePayer, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: recentBlockhash, lastValidBlockHeight: 1000n }, tx),
    (tx) =>
      appendTransactionMessageInstructions(
        [
          getSetComputeUnitLimitInstruction({ units: 30000 }),
          getSetComputeUnitPriceInstruction({ microLamports: 1 }),
          getCreateAssociatedTokenInstruction({
            payer: createNoopSigner(feePayer),
            ata: destination,
            owner,
            mint,
            tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
          }),
          getTransferCheckedInstruction(
            { source, mint, destination, authority: client, amount: 2000n, decimals: 6 },
            { programAddress: TOKEN_2022_PROGRAM_ADDRESS },
          ),
        ],
        tx,
      ),
  );
  const wire = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(message));
  const tok = encodePayment({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: wire } });
  assert.equal(paymentAuthority(decodePayment(tok)), client.address);
});

test("a transaction longer than Solana allows is refused before any facilitator call", async () => {
  const oversized = txBase64("big", 0, { transfers: 60 });
  assert.ok(Buffer.from(oversized, "base64").length > 1232);
  assert.equal(paymentClaimKey({ x402Version: 1, scheme: "exact", network: "solana", payload: { transaction: oversized } }), null);
  assert.equal(authorityOf(oversized), null);
  const h = harness();
  assert.equal(errorCode(await h.handler({}, paid(token("pay-20", 0, { transfers: 60 })))), "INVALID_PAYMENT");
  assert.deepEqual(paymentEvents(h.events), []);
});

test("a payment token longer than any real payment is refused before it is decoded", async () => {
  const h = harness();
  const huge = "A".repeat(MAX_PAYMENT_TOKEN_LENGTH + 1);
  assert.equal(errorCode(await h.handler({}, paid(huge))), "INVALID_PAYMENT");
  assert.equal(paymentTokenAuthority(huge), null);
  assert.deepEqual(paymentEvents(h.events), []);
  assert.ok(token("pay-21").length < MAX_PAYMENT_TOKEN_LENGTH / 2, "a real payment token is far below the limit");
});

test("paymentTokenAuthority names the signer of an unsettled token", () => {
  assert.equal(paymentTokenAuthority(token("pay-22", 0, { payer: "wallet-c" })), walletOf("wallet-c"));
  assert.equal(paymentTokenAuthority(token("pay-23", 0, { transfers: 2 })), null);
  assert.equal(paymentTokenAuthority("not-a-payment"), null);
});

test("concurrent calls on a cold cache ask the facilitator for its fee payer once", async () => {
  const h = harness();
  const results = await Promise.all(Array.from({ length: 5 }, () => h.handler({}, {})));
  assert.ok(results.every((r) => errorCode(r) === "PAYMENT_REQUIRED"));
  assert.equal(h.events.filter((e) => e === "supported").length, 1);
});

test("a failed fee-payer lookup is not cached, so the next call asks again", async () => {
  let fail = true;
  const events: string[] = [];
  const settleFirst = createSettleFirstPaidTools(CONFIG, {
    facilitator: {
      supported: async () => {
        events.push("supported");
        if (fail) throw new Error("facilitator down");
        return { kinds: [{ scheme: "exact", network: "solana", extra: { feePayer: walletOf("fee-payer") } }] };
      },
      verify: async () => ({ isValid: true }),
      settleBody: async () => ({ success: true, transaction: "sig", network: "solana" }),
    },
    claimsDir: tempDir(),
    log: () => {},
    info: () => {},
  });
  let handler: Handler | undefined;
  settleFirst({ tool: (...args: unknown[]) => void (handler = args[4] as Handler) })("echo", "Echo", "$0.01", {}, {}, async () => ({ content: [] }));
  assert.equal(errorCode(await handler!({}, {})), "PRICE_COMPUTE_FAILED");
  fail = false;
  assert.equal(errorCode(await handler!({}, {})), "PAYMENT_REQUIRED");
  assert.equal(events.length, 2);
});
