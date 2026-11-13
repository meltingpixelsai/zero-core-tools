/**
 * Settle-first x402 paid tools.
 *
 * mcpay 0.1.17's `paidTool` (dist/handler/server/plugins/with-x402.js) verifies
 * the payment, runs the tool, and settles only after the tool succeeds. So a
 * payment that never settles still gets the tool's side effects for free: a
 * payer who moves the funds after verify, or one signed payment sent many times
 * in parallel (every copy passes verify before any of them settles).
 *
 * This version takes the payment before the tool runs:
 *   1. claim the payment once (keyed on the signed transaction message, so
 *      re-encodings of the same payment share one key);
 *   2. verify it with the facilitator;
 *   3. settle it;
 *   4. only then run the tool.
 * A payment the facilitator definitely did not settle releases its claim and
 * never runs the tool. A settlement without a final answer (no reply, a busy or
 * failing facilitator, "settlement_pending") is not a failure: the payment may
 * still be taken. The call asks again with the identical request, which the
 * facilitator answers with the recorded outcome instead of paying twice. If no
 * final answer comes in time the claim is KEPT, the caller is told the outcome
 * is unknown and is not offered a new payment, and presenting the same payment
 * with the same call later asks once more: the tool then runs, or the claim is
 * released because nothing was taken.
 * Resuming needs the payment's resume code as well. The code is made when the
 * settle request is recorded, only its SHA-256 is kept in the claim, and the
 * caller gets it with the answer that the outcome is unknown (`resumeCode`),
 * to present as `_meta["x402/resume"]` or an X-PAYMENT-RESUME header. A payment
 * is public once it is on chain and a call's arguments can sometimes be guessed;
 * the code is known only to whoever received that answer. A caller may also
 * choose the code itself and send it the same way with its first call: that
 * call's settlement can then be resumed even if the call is cut off before it
 * answers. A call that was cut off and carried no code of the caller's own has
 * handed out none, so its settlement cannot be resumed.
 * A call is answered inside about 50 seconds whatever the facilitator does, so
 * that a caller with the usual 60-second limit gets the answer, and the code.
 * A tool may name a readiness check (`preflight`) for what it depends on; it
 * runs between 2 and 3, and a refusal releases the claim and settles nothing.
 * Claims are marker files in one directory shared by every server that takes
 * the same wallet's payments (default ~/.x402-claims), so one payment sent to
 * several servers at once runs one tool, and a replay after a restart is
 * refused. A settled claim is kept for 24 hours. A tool that fails after
 * settlement has been paid for: the result says so (x402/payment-response) and
 * the server logs it.
 *
 * Payment tokens and transactions longer than any real payment are refused
 * before they are parsed, so a crafted payment cannot tie up the process.
 *
 * Requirement building and payment-token parsing follow mcpay 0.1.17
 * (MIT License, Copyright (c) MCPay). Solana ("svm") recipients only.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { decodePayment } from "x402/schemes";
import { findMatchingPaymentRequirements, processPriceToAtomicAmount, toJsonSafe } from "x402/shared";
import { SupportedSVMNetworks } from "x402/types";
import type { PaymentPayload, PaymentRequirements, VerifyResponse } from "x402/types";
import { useFacilitator } from "x402/verify";

type Price = Parameters<typeof processPriceToAtomicAmount>[0];
type Network = PaymentRequirements["network"];

export interface SettleFirstConfig {
  facilitator: { url: `${string}://${string}` };
  recipient: { svm: { address: string; isTestnet?: boolean } };
  version?: number;
}

export interface ToolResult {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

/** The settled payment, passed to the tool callback as `extra.x402Settlement`. */
export interface X402Settlement {
  /** The wallet that signed the payment's token transfer, read from the transaction itself. */
  payer: string;
  transaction: string;
  network: string;
}

/**
 * A settle reply as a facilitator may really send it (its reason codes are not limited to the ones x402's types
 * list), with the HTTP status it came with (absent when a facilitator object returns the reply directly).
 */
export interface SettleReply {
  success?: boolean;
  errorReason?: string;
  transaction?: string;
  network?: string;
  payer?: string;
  httpStatus?: number;
}

export interface FacilitatorClient {
  verify: (payload: PaymentPayload, requirements: PaymentRequirements) => Promise<VerifyResponse>;
  /**
   * One settle request with exactly this body, answered within `timeoutMs`. It resolves with the facilitator's
   * reply and HTTP status whatever the status is, and rejects only when no reply came (network error, timeout).
   */
  settleBody: (body: string, timeoutMs: number) => Promise<SettleReply>;
  supported: () => Promise<{ kinds: Array<{ scheme: string; network: string; extra?: Record<string, unknown> }> }>;
}

/** The MCP server's `tool(name, description, paramsSchema, annotations, cb)` overload, as mcpay calls it. */
type ToolRegistrar = { tool: (...args: unknown[]) => unknown };

export interface PaidToolOptions<A> {
  /** Cheap input checks that run before any payment is asked for or taken. Return a message to refuse the call. */
  precheck?: (args: A) => Promise<string | null> | string | null;
  /**
   * A readiness check for what the tool depends on (the browser, for the browser tools). It runs once the payment
   * has been verified and before it is settled, so only a caller holding a valid payment can set it off. Return a
   * message to refuse the call: the payment is then not settled and its claim is released, so the same payment can
   * be presented again later. A check that throws refuses the call the same way. Keep the check short: a caller
   * that gives up while it runs is still settled and the tool still runs, as for any call in flight (a cancellation
   * is accepted and ignored, see request-guard.ts).
   *
   * A call that resumes a settlement an earlier call left unresolved runs the check too, before the facilitator is
   * asked again. That payment may already be taken, so a refusal there promises nothing: the settlement stays as it
   * is, the check's own message is not passed on, and the caller is told to present the payment again later.
   */
  preflight?: (args: A) => Promise<string | null> | string | null;
}

/** What a caller is told when a preflight check throws instead of answering. */
export const PREFLIGHT_FAILED = "The service is not ready for this call. No payment was taken. Try again later.";

export interface SettleFirstDeps {
  facilitator?: FacilitatorClient;
  /** Claim directory shared by every server paid to the same wallet. Default: X402_CLAIMS_DIR or ~/.x402-claims */
  claimsDir?: string;
  now?: () => number;
  log?: (line: string) => void;
  /** Startup information (the claim directory in use). Default: console.log */
  info?: (line: string) => void;
  /** The wait between two settle requests for one payment. Default: a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** How long the facilitator's answer to a verify request is waited for. Default: 15 seconds. */
  verifyTimeoutMs?: number;
  /** The same for its list of supported payment kinds (the fee payers). Default: 10 seconds. */
  supportedTimeoutMs?: number;
}

/** The error code of a call whose payment may or may not have been taken. Its result offers no new payment. */
export const SETTLEMENT_UNRESOLVED = "SETTLEMENT_UNRESOLVED";

const CLAIM_TTL_MS = 24 * 60 * 60 * 1000;
const PRUNE_EVERY_MS = 10 * 60 * 1000;
/**
 * How long a call keeps asking for the outcome of the settlement it started, counted from its first settle request
 * (verify and the readiness check come before it, the tool's own run after). Short enough that a caller with the
 * usual 60-second limit for a call normally still gets the answer; the facilitator itself may take 100 seconds.
 */
const SETTLE_BUDGET_MS = 45 * 1000;
/** The same for a call that presents a payment whose settlement an earlier call left unresolved. */
const SETTLE_AGAIN_BUDGET_MS = 20 * 1000;
/**
 * A call's settle requests also stop this long after the call came in, whatever verify and the readiness check took
 * of it: the answer, and with it the resume code, must reach a caller whose own limit for a call is 60 seconds. One
 * settle request is always made (SETTLE_REQUEST_MIN_MS), so the answer can come a few seconds later than this.
 */
const CALL_BUDGET_MS = 50 * 1000;
/**
 * How long the facilitator's answer to verify, and to supported, is waited for. Neither request moves money, so one
 * that is given up on is a refusal with nothing taken.
 */
const VERIFY_TIMEOUT_MS = 15 * 1000;
const SUPPORTED_TIMEOUT_MS = 10 * 1000;
/** No settle request is given less time than this, however little of the budget is left. */
const SETTLE_REQUEST_MIN_MS = 3 * 1000;
/** Waits between the settle requests of one call; the last one repeats. */
const SETTLE_ASK_AGAIN_DELAYS_MS = [2_000, 3_000, 5_000, 10_000];
/** A bound on one call's settle requests that does not depend on the clock. */
const SETTLE_MAX_REQUESTS = 12;
/**
 * A claim still marked "settling" after this long was left by a process that is gone (a call holds one for
 * SETTLE_BUDGET_MS plus one request at most), so a later call may ask the facilitator about it.
 */
const SETTLING_STALE_MS = 10 * 60 * 1000;
/** A claim's lock is held for a few file operations; one this old was left by a process that died holding it. */
const LOCK_STALE_MS = 60 * 1000;
const END_CLAIM_TRIES = 20;
const END_CLAIM_WAIT_MS = 50;
/**
 * A settlement is resumed only this long after its first request. The facilitator keeps a payment's outcome for 24
 * hours; later than that its answer to the same body would be a new judgement of an expired payment, not the outcome.
 */
const RESUME_WINDOW_MS = 23 * 60 * 60 * 1000;
/** What the caller of an unresolved settlement is told to wait before presenting the payment again. */
const UNRESOLVED_RETRY_SECONDS = 30;
/** How often one claim's refused resumes are logged, per reason, and how many claims that is remembered for. */
const DENIED_LOG_EVERY_MS = 10 * 60 * 1000;
const DENIED_LOG_MAX_ENTRIES = 1000;
/** A settle request body holds one payment token's content and one requirement; a stored one longer is not ours. */
const MAX_SETTLE_BODY_LENGTH = 16 * 1024;

/**
 * Settle replies that are not a final answer: the payment may still be taken, or already was. The first five are
 * PayAI's: "settlement_pending" and "duplicate_settlement" (its API description: "treat this as unresolved, not
 * failed, and re-submit the identical body"), a request still in flight under an idempotency key, and its two
 * server-side failures, which it never records as an outcome. The last two are what x402's reference facilitator
 * answers once it has sent the transaction.
 */
const UNRESOLVED_REASONS = new Set([
  "settlement_pending",
  "duplicate_settlement",
  "idempotency_key_in_flight",
  "internal_server_error",
  "service_unavailable",
  "unexpected_settle_error",
  "settle_exact_svm_transaction_confirmation_timed_out",
]);

/** Where a caller presents a resume code: this `_meta` key of the tool call, or this HTTP header. */
export const RESUME_META_KEY = "x402/resume";
export const RESUME_HEADER = "X-PAYMENT-RESUME";
const HOW_TO_RESUME = `with the resume code given here as _meta["${RESUME_META_KEY}"] (or the ${RESUME_HEADER} header)`;

/**
 * What the caller of an unresolved settlement is told. `withCode`: the answer carries the payment's resume code (a
 * settlement recorded before resume codes has none, and is resumed without one).
 */
const unresolvedMessage = (withCode: boolean): string =>
  "This payment was sent for settlement and the outcome is not known yet: it may still be taken. Do not send a new payment for this call. " +
  `Present the same payment with the same call again${withCode ? `, ${HOW_TO_RESUME},` : ""} to get the result, or a definite answer that nothing was taken.`;
const IN_PROGRESS_MESSAGE =
  "An earlier call with this payment is still in progress. Do not send a new payment for this call. " +
  "That call's answer carries the result, or a resume code to present with the same payment and the same call. " +
  "If that call was cut off and carried a resume code of your own, present the same payment, the same call and that code again in ten minutes.";
const notRecordedMessage = (withCode: boolean): string =>
  "This payment was settled, but the call could not be recorded as paid, so it was not run. Do not send a new payment for this call. " +
  `Present the same payment with the same call again after the time given${withCode ? `, ${HOW_TO_RESUME},` : ""} to get the result.`;
const RESUME_CODE_MESSAGE =
  "The outcome of this payment is not known, and this call did not present the payment's resume code. Do not send a new payment for this call. " +
  `The call that sent the payment for settlement was given a resume code with its answer, or sent one of its own: present the same payment with the same call and that code as _meta["${RESUME_META_KEY}"] (or the ${RESUME_HEADER} header).`;
/** Sent with every offer of a payment: how a caller keeps its way back to a call that is cut off. */
const RESUME_HINT = {
  meta: RESUME_META_KEY,
  header: RESUME_HEADER,
  note:
    "Optional. Send 32 random bytes as base64url (43 characters), new for each payment, with the paid call. " +
    "If the call is cut off, or answers SETTLEMENT_UNRESOLVED, the same payment, the same call and that code get the result without a second payment.",
};
const CLAIM_UNAVAILABLE_MESSAGE = "The service cannot record payments right now, so this call sent nothing for settlement. Try again later.";
const CLAIM_UNREADABLE_MESSAGE =
  "The service cannot read this payment's record right now. Do not send a new payment for this call. Present the same payment with the same call again later.";
const NOT_READY_MESSAGE =
  "The service is not ready to run this call yet, and the outcome of its payment is not known. Do not send a new payment for this call. " +
  "Present the same payment with the same call again later, with the same resume code if this call presented one.";

/** A resume code: 32 random bytes as base64url. */
const RESUME_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const RESUME_HASH_PATTERN = /^[0-9a-f]{64}$/;

function newResumeCode(): string {
  return randomBytes(32).toString("base64url");
}

/** What a claim keeps of its resume code. The code itself is never written anywhere. */
function resumeCodeHash(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

/** Whether `code` is the resume code whose hash a claim holds. Anything that is not shaped like a code is not. */
function resumeCodeMatches(code: string | undefined, hash: string): boolean {
  if (typeof code !== "string" || !RESUME_CODE_PATTERN.test(code) || !RESUME_HASH_PATTERN.test(hash)) return false;
  return timingSafeEqual(Buffer.from(resumeCodeHash(code), "hex"), Buffer.from(hash, "hex"));
}

/**
 * A claim's record. `t`: when it was last written. `call` names the call (tool and arguments) the payment was
 * presented with; a "pending" record written by the previous version of this file has none. `o` marks the call that
 * owns a settlement in progress; `body` is the settle request, so a later call can resume it; `f` is when that
 * request was first sent; `rc` is the SHA-256 of the payment's resume code (a record written by the version of this
 * file before resume codes has none).
 */
type ClaimRecord =
  | { s: "pending"; t: number; call?: string }
  | { s: "settling"; t: number; f: number; o: string; call: string; body: string; rc?: string; tx?: string; paid?: PaidMark }
  | { s: "unresolved"; t: number; f: number; call: string; body: string; rc?: string; tx?: string; paid?: PaidMark }
  | { s: "settled"; t: number; tx?: string };

/**
 * A settlement this call owns: its owner mark and the payment's resume code. A settlement recorded before resume
 * codes has no code, and is resumed without one for as long as it lasts.
 */
type OwnedSettlement = { owner: string; code?: string };

/** `rc` of a record whose resume-code hash is there and cannot be read: nothing matches it. */
const UNREADABLE_RESUME_HASH = "";

/**
 * The facilitator has answered that the payment settled, and the tool has not run: the claim could not be marked
 * settled then. A call that resumes such a claim needs no further answer from the facilitator.
 */
type PaidMark = { tx: string; network: string };

/** How the call that owns a settlement ends it. */
type ClaimEnd = { s: "settled"; tx: string } | { s: "unresolved"; tx: string; paid?: PaidMark } | { s: "released" };

function parseClaim(text: string): ClaimRecord | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object") return null;
  const rec = value as Record<string, unknown>;
  if (typeof rec.t !== "number") return null;
  const tx = typeof rec.tx === "string" ? { tx: rec.tx } : {};
  if (rec.s === "pending") return { s: "pending", t: rec.t, ...(typeof rec.call === "string" ? { call: rec.call } : {}) };
  if (rec.s === "settled") return { s: "settled", t: rec.t, ...tx };
  if (typeof rec.call !== "string" || typeof rec.f !== "number") return null;
  if (typeof rec.body !== "string" || rec.body.length > MAX_SETTLE_BODY_LENGTH) return null;
  const mark = rec.paid as { tx?: unknown; network?: unknown } | null | undefined;
  const paid = mark && typeof mark === "object" && typeof mark.tx === "string" && typeof mark.network === "string" ? { paid: { tx: mark.tx, network: mark.network } } : {};
  // A resume-code hash this code cannot read is not "no resume code", and it is not a used payment either: the
  // record is kept, with a hash that nothing matches (see `stateOf`).
  const rc = rec.rc === undefined ? {} : { rc: typeof rec.rc === "string" && RESUME_HASH_PATTERN.test(rec.rc) ? rec.rc : UNREADABLE_RESUME_HASH };
  if (rec.s === "unresolved") return { s: "unresolved", t: rec.t, f: rec.f, call: rec.call, body: rec.body, ...rc, ...tx, ...paid };
  if (rec.s === "settling" && typeof rec.o === "string") return { s: "settling", t: rec.t, f: rec.f, o: rec.o, call: rec.call, body: rec.body, ...rc, ...tx, ...paid };
  return null;
}
const FEE_PAYER_TTL_MS = 10 * 60 * 1000;
/** A failed verify may mean the facilitator rotated its fee payer, but refresh at most this often. */
const FEE_PAYER_REFRESH_MIN_MS = 30 * 1000;

/**
 * Single-use payment claims: one marker file per payment, created with O_EXCL,
 * so the claim is atomic across every process that shares the directory.
 */
export class ClaimStore {
  private lastPrune = 0;

  constructor(
    private readonly dir: string,
    private readonly now: () => number,
    private readonly log: (line: string) => void,
  ) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  private file(key: string): string {
    return path.join(this.dir, key.replace(/[^A-Za-z0-9_-]/g, "_") + ".claim");
  }

  private create(key: string): number {
    return fs.openSync(this.file(key), "wx", 0o600);
  }

  /**
   * Take the claim for `call`; false when any process already holds it. Throws when the directory cannot be
   * written.
   */
  tryClaim(key: string, call: string): boolean {
    this.pruneOccasionally();
    let fd: number;
    try {
      fd = this.create(key);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EEXIST") return false;
      if (code !== "ENOENT") throw err;
      // The directory was removed while the server ran: recreate it once.
      fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      try {
        fd = this.create(key);
      } catch (retryErr) {
        if ((retryErr as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw retryErr;
      }
    }
    try {
      fs.writeSync(fd, JSON.stringify({ s: "pending", t: this.now(), call }));
    } finally {
      fs.closeSync(fd);
    }
    return true;
  }

  private lockFile(key: string): string {
    return this.file(key).slice(0, -".claim".length) + ".lock";
  }

  /**
   * The claim's record; null when there is no claim file, or when it holds nothing this code can read. Throws when
   * the file is there and cannot be read: not knowing what a claim says is different from knowing it is used.
   */
  private read(key: string): ClaimRecord | null {
    let text: string;
    try {
      text = fs.readFileSync(this.file(key), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
    return parseClaim(text);
  }

  /** Replaces the claim's record in one step: written beside it, then renamed over it. */
  private write(key: string, record: ClaimRecord): void {
    const file = this.file(key);
    const tmp = `${file}.${randomUUID()}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(record), { mode: 0o600, flag: "wx" });
      fs.renameSync(tmp, file);
    } catch (err) {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // It was never written.
      }
      throw err;
    }
  }

  /**
   * Runs `change` holding the claim's lock, so that reading a claim and then replacing it is one step for every
   * process that shares the directory. `change` must not wait for anything. Returns null when another process holds
   * the lock right now.
   */
  private locked<T>(key: string, change: () => T): { value: T } | null {
    const lock = this.lockFile(key);
    const mine = randomUUID();
    const take = (): boolean => {
      let fd: number;
      try {
        fd = fs.openSync(lock, "wx", 0o600);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw err;
      }
      try {
        fs.writeSync(fd, mine);
      } finally {
        fs.closeSync(fd);
      }
      return true;
    };
    if (!take()) {
      // A live holder keeps the lock for a few file operations. One this old died holding it: clear it once.
      // Looking at the lock and deleting it are two steps, so two processes that clear the same dead lock at the
      // same moment can both end up inside `change`. The owner marks keep that harmless: of two calls that change
      // one claim, only the one whose mark the record carries acts on the outcome.
      try {
        if (this.now() - fs.statSync(lock).mtimeMs <= LOCK_STALE_MS) return null;
        fs.unlinkSync(lock);
      } catch {
        return null;
      }
      if (!take()) return null;
    }
    try {
      return { value: change() };
    } finally {
      // Remove the lock only while it is still this holder's: if it was cleared as stale and taken by another
      // process meanwhile, it is theirs.
      try {
        if (fs.readFileSync(lock, "utf8") === mine) fs.unlinkSync(lock);
      } catch {
        // Already gone.
      }
    }
  }

  /**
   * The claimant has verified the payment and is about to send it for settlement: record the call and the exact
   * request, so the settlement can be resumed if this call cannot finish it, and the hash of a new resume code, so
   * that only a caller this call has answered can resume it. Returns the mark that makes this call the settlement's
   * owner with that code, or null when the record could not be written (nothing has been sent then). `chosen`: the
   * code the caller sent with this first presentation of the payment; it is used instead of a new one, so a caller
   * whose call is cut off before the answer still holds the code.
   */
  markSettling(key: string, call: string, body: string, chosen?: string): OwnedSettlement | null {
    if (body.length > MAX_SETTLE_BODY_LENGTH) {
      // A record this long could not be read back, and a settlement that cannot be resumed is not started.
      this.log(`[x402] settle request too long to record (${body.length} characters): shorten the tool's description`);
      return null;
    }
    const owner = randomUUID();
    const code = chosen !== undefined && RESUME_CODE_PATTERN.test(chosen) ? chosen : newResumeCode();
    const now = this.now();
    try {
      this.write(key, { s: "settling", t: now, f: now, o: owner, call, body, rc: resumeCodeHash(code) });
      return { owner, code };
    } catch (err) {
      this.log(`[x402] could not record a settlement before sending it: ${String(err)}`);
      return null;
    }
  }

  /**
   * What a call that presents an already claimed payment may do:
   *   "used"    the payment was used, or is in use by a different call (also: a claim whose content is not a record
   *             this code knows, a payment claimed long ago and never sent for settlement, a settlement too old to
   *             ask about);
   *   "open"    an earlier presentation of this same call is at work on it right now;
   *   "resume"  the call's settlement was left unresolved (or its owner is gone) and `code` is the payment's resume
   *             code: this call may ask about it again (a record from before resume codes holds no hash and asks for
   *             none);
   *   "denied"  the same, but `code` is missing or is not the payment's resume code;
   *   "unknown" the claim file is there and could not be read, or its resume-code hash could not.
   * Reads only.
   */
  heldFor(key: string, call: string, code?: string): "used" | "open" | "resume" | "denied" | "unknown" {
    let rec: ClaimRecord | null;
    try {
      rec = this.read(key);
    } catch (err) {
      // Not knowing what the claim says is no ground for offering a new payment.
      this.log(`[x402] could not read a payment claim: ${String(err)}`);
      return "unknown";
    }
    return this.stateOf(rec, call, code);
  }

  /** `heldFor`, for a record already read: the decision and what it is taken from are one read. */
  private stateOf(rec: ClaimRecord | null, call: string, code?: string): "used" | "open" | "resume" | "denied" | "unknown" {
    if (!rec || rec.s === "settled" || rec.call !== call) return "used";
    const fresh = this.now() - rec.t < SETTLING_STALE_MS;
    // A claim still "pending" after this long was left by a process that is gone before anything was sent, or by a
    // verify that hangs far beyond the life of the payment (a Solana payment expires in about a minute).
    if (rec.s === "pending") return fresh ? "open" : "used";
    if (this.now() - rec.f >= RESUME_WINDOW_MS) return "used";
    if (rec.s === "settling" && fresh) return "open";
    if (rec.rc === undefined) return "resume";
    // A hash that cannot be read tells nothing about who may resume, and is no ground for offering a new payment.
    if (!RESUME_HASH_PATTERN.test(rec.rc)) return "unknown";
    return resumeCodeMatches(code, rec.rc) ? "resume" : "denied";
  }

  /**
   * Makes the calling call the owner of a settlement that `heldFor` reports as "resume" for `code`. Returns the
   * owner mark, the payment's resume code, the request to send again, the transaction the facilitator named (if any)
   * and the mark of a payment already known to be settled (if any); or "open" / "used" when another call got there
   * first, or "denied" when `code` is not the payment's resume code. The code stays the same for the life of the
   * claim, so an answer that is lost on its way to the caller does not take the caller's way back with it. A record
   * from before resume codes has no code and is given none: whoever resumed it first would otherwise lock out the
   * caller it belongs to.
   */
  takeOver(key: string, call: string, code?: string): (OwnedSettlement & { body: string; tx: string; paid?: PaidMark }) | "open" | "used" | "denied" {
    type Taken = (OwnedSettlement & { body: string; tx: string; paid?: PaidMark }) | "open" | "used" | "denied";
    const refusal = (state: "used" | "open" | "denied" | "unknown"): "open" | "used" | "denied" => (state === "unknown" ? "open" : state);
    let taken: { value: Taken } | null;
    try {
      taken = this.locked(key, (): Taken => {
        // One read: the state is decided from the very record the new one is written from.
        const rec = this.read(key);
        const state = this.stateOf(rec, call, code);
        if (state !== "resume") return refusal(state);
        const held = rec as Extract<ClaimRecord, { s: "settling" | "unresolved" }>;
        const owner = randomUUID();
        const kept = { ...(held.rc !== undefined ? { rc: held.rc } : {}), ...(held.tx ? { tx: held.tx } : {}), ...(held.paid ? { paid: held.paid } : {}) };
        this.write(key, { s: "settling", t: this.now(), f: held.f, o: owner, call, body: held.body, ...kept });
        // `stateOf` has just matched `code` against the record's hash, where it has one.
        return { owner, ...(held.rc !== undefined && code !== undefined ? { code } : {}), body: held.body, tx: held.tx ?? "", ...(held.paid ? { paid: held.paid } : {}) };
      });
    } catch (err) {
      this.log(`[x402] could not take over an unresolved settlement: ${String(err)}`);
      return "open";
    }
    if (taken) return taken.value;
    // Another process is changing this claim right now.
    const state = this.heldFor(key, call, code);
    return state === "resume" ? "open" : refusal(state);
  }

  /**
   * Ends a settlement, if `owner` still owns it: the claim becomes settled, or unresolved (kept, resumable), or is
   * released (deleted). "lost": another call has taken the settlement over, and this call must not act on its
   * outcome. "busy": another process holds the lock right now, try again. "error": the record could not be changed
   * (the claim is still held, as a settlement in progress).
   *
   * `unlocked` is for an owner that could not get the lock in any reasonable time: the change is made without it.
   * Whoever holds the lock that long is not at work on this claim, and the owner check still decides.
   */
  end(key: string, owner: string, end: ClaimEnd, unlocked = false): "done" | "lost" | "busy" | "error" {
    const change = (): "done" | "lost" => {
      const rec = this.read(key);
      if (!rec || rec.s !== "settling" || rec.o !== owner) return "lost";
      if (end.s === "released") fs.unlinkSync(this.file(key));
      else if (end.s === "settled") this.write(key, { s: "settled", t: this.now(), tx: end.tx });
      else {
        // A transaction the facilitator named earlier stays on record when its later replies name none, and so
        // does the mark of a payment known to be settled.
        const tx = end.tx || rec.tx;
        const paid = end.paid ?? rec.paid;
        const rc = rec.rc !== undefined ? { rc: rec.rc } : {};
        this.write(key, { s: "unresolved", t: this.now(), f: rec.f, call: rec.call, body: rec.body, ...rc, ...(tx ? { tx } : {}), ...(paid ? { paid } : {}) });
      }
      return "done";
    };
    try {
      if (unlocked) return change();
      const ended = this.locked(key, change);
      return ended ? ended.value : "busy";
    } catch (err) {
      this.log(`[x402] could not record a settlement's outcome (claim still held): ${String(err)}`);
      return "error";
    }
  }

  release(key: string): void {
    try {
      fs.unlinkSync(this.file(key));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        this.log(`[x402] could not release payment claim: ${String(err)}`);
      }
    }
  }

  has(key: string): boolean {
    return fs.existsSync(this.file(key));
  }

  /**
   * Delete claims older than 24 hours (their payments can no longer settle, and the facilitator keeps an outcome
   * that long), and what a process left behind when it died: half-written records, and locks whose claim is gone
   * (a lock whose claim is still there is cleared by the next call that needs it, see `locked`).
   */
  private pruneOccasionally(): void {
    const now = this.now();
    if (now - this.lastPrune < PRUNE_EVERY_MS) return;
    this.lastPrune = now;
    try {
      const names = fs.readdirSync(this.dir);
      const claimed = new Set(names.filter((name) => name.endsWith(".claim")).map((name) => name.slice(0, -".claim".length)));
      for (const name of names) {
        const orphanLock = name.endsWith(".lock") && !claimed.has(name.slice(0, -".lock".length));
        const maxAge = name.endsWith(".claim") ? CLAIM_TTL_MS : orphanLock || name.endsWith(".tmp") ? LOCK_STALE_MS : null;
        if (maxAge === null) continue;
        const file = path.join(this.dir, name);
        try {
          if (now - fs.statSync(file).mtimeMs > maxAge) fs.unlinkSync(file);
        } catch {
          // Another process pruned or released it first.
        }
      }
    } catch (err) {
      this.log(`[x402] could not prune payment claims: ${String(err)}`);
    }
  }
}

/** Solana compact-u16 ("shortvec"): up to 3 bytes of 7 bits each. */
function readShortVec(bytes: Uint8Array, offset: number): { value: number; next: number } | null {
  let value = 0;
  for (let i = 0; i < 3; i++) {
    if (offset + i >= bytes.length) return null;
    const byte = bytes[offset + i];
    value |= (byte & 0x7f) << (7 * i);
    if ((byte & 0x80) === 0) return { value, next: offset + i + 1 };
  }
  return null;
}

/** Solana's packet limit: no transaction that can settle is longer. */
const MAX_TRANSACTION_BYTES = 1232;
/** An x402 token wraps one such transaction in base64 JSON; a longer string is not a payment. */
export const MAX_PAYMENT_TOKEN_LENGTH = 4096;

/** The message bytes of a base64 Solana wire transaction: everything after the signature section. */
function wireMessage(transaction: unknown): Buffer | null {
  if (typeof transaction !== "string" || transaction.length > Math.ceil(MAX_TRANSACTION_BYTES / 3) * 4) return null;
  const bytes = Buffer.from(transaction, "base64");
  if (bytes.length > MAX_TRANSACTION_BYTES) return null;
  const signatures = readShortVec(bytes, 0);
  if (!signatures || signatures.value === 0) return null;
  const messageStart = signatures.next + signatures.value * 64;
  if (messageStart >= bytes.length) return null;
  return bytes.subarray(messageStart);
}

/**
 * Claim key for an "exact" Solana payment: SHA-256 of the transaction message
 * (the bytes after the signature section). The payer's signature covers
 * exactly these bytes, so every encoding of a payment that could settle has the
 * same key. Returns null for anything else.
 */
export function paymentClaimKey(payment: PaymentPayload): string | null {
  const message = wireMessage((payment.payload as { transaction?: unknown }).transaction);
  return message ? "svm-" + createHash("sha256").update(message).digest("hex") : null;
}

const TRANSFER_CHECKED = 12;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = BASE58[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}

function fromBase58(text: string): Buffer {
  let n = 0n;
  for (const ch of text) n = n * 58n + BigInt(BASE58.indexOf(ch));
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

/** Compared as raw key bytes, so checking an instruction's program costs no encoding. */
const TOKEN_PROGRAM_KEYS = [
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022
].map(fromBase58);

/**
 * The paying wallet: the signer that authorizes the payment's one token
 * TransferChecked, read from the signed transaction. The facilitator's reply
 * is not used for this, because x402's reference facilitator reports its own
 * fee payer as "payer". Returns null unless the message (legacy or v0) has
 * exactly one TransferChecked and its authority is a signer other than the
 * fee payer (account 0): the facilitator signs as fee payer for anyone, so a
 * transfer it "authorizes" (as an approved delegate) proves no one's wallet.
 */
export function paymentAuthority(payment: PaymentPayload): string | null {
  const msg = wireMessage((payment.payload as { transaction?: unknown }).transaction);
  if (!msg) return null;
  let o = 0;
  if (msg[0] & 0x80) {
    if ((msg[0] & 0x7f) !== 0) return null; // only version 0 of the versioned format
    o = 1;
  }
  if (o + 3 > msg.length) return null;
  const signerCount = msg[o];
  o += 3;
  const keys = readShortVec(msg, o);
  if (!keys) return null;
  const keysStart = keys.next;
  o = keysStart + keys.value * 32 + 32; // static account keys, then the recent blockhash
  if (o > msg.length) return null;
  const key = (index: number) => msg.subarray(keysStart + index * 32, keysStart + (index + 1) * 32);
  const instructions = readShortVec(msg, o);
  if (!instructions) return null;
  o = instructions.next;
  let transfers = 0;
  let authority = -1;
  for (let i = 0; i < instructions.value; i++) {
    if (o >= msg.length) return null;
    const programIndex = msg[o++];
    const accounts = readShortVec(msg, o);
    if (!accounts) return null;
    const accountIndexes = msg.subarray(accounts.next, accounts.next + accounts.value);
    const data = readShortVec(msg, accounts.next + accounts.value);
    if (!data) return null;
    const dataBytes = msg.subarray(data.next, data.next + data.value);
    o = data.next + data.value;
    if (o > msg.length) return null;
    if (programIndex >= keys.value) continue;
    const program = key(programIndex);
    if (!TOKEN_PROGRAM_KEYS.some((k) => k.equals(program))) continue;
    if (dataBytes[0] !== TRANSFER_CHECKED) continue;
    transfers++;
    if (accountIndexes.length < 4) return null;
    authority = accountIndexes[3];
  }
  if (transfers !== 1 || authority <= 0 || authority >= signerCount || authority >= keys.value) return null;
  return base58(key(authority));
}

/**
 * The paying wallet a payment token names, before the payment is verified or
 * settled. Only good for refusing a call before any money moves.
 */
export function paymentTokenAuthority(token: string): string | null {
  if (token.length > MAX_PAYMENT_TOKEN_LENGTH) return null;
  try {
    return paymentAuthority(decodePayment(token));
  } catch {
    return null;
  }
}

/** Read the payment token from MCP `_meta["x402/payment"]` or an X-PAYMENT header, as mcpay does. */
export function readPaymentToken(extra: unknown): string | undefined {
  const ex = (extra ?? {}) as { _meta?: Record<string, unknown>; requestInfo?: { headers?: unknown } };
  const meta = ex._meta?.["x402/payment"];
  if (typeof meta === "string") return meta;
  const headers = ex.requestInfo?.headers;
  if (!headers) return undefined;
  if (typeof (headers as { get?: unknown }).get === "function") {
    const value = (headers as { get: (name: string) => string | null }).get("X-PAYMENT");
    return value ?? undefined;
  }
  if (typeof headers === "object") {
    const rec = headers as Record<string, unknown>;
    const direct = rec["X-PAYMENT"] ?? rec["x-payment"];
    return typeof direct === "string" ? direct : undefined;
  }
  return undefined;
}

/**
 * Read the resume code from MCP `_meta["x402/resume"]` or an X-PAYMENT-RESUME header. Only a string shaped like a
 * resume code is returned, so nothing else a caller sends here is ever hashed or compared. `_meta` comes first; a
 * value there that is not shaped like a code does not hide one in the header.
 */
export function readResumeCode(extra: unknown): string | undefined {
  const ex = (extra ?? {}) as { _meta?: Record<string, unknown>; requestInfo?: { headers?: unknown } };
  const shaped = (value: unknown): string | undefined => (typeof value === "string" && RESUME_CODE_PATTERN.test(value) ? value : undefined);
  const fromMeta = shaped(ex._meta?.[RESUME_META_KEY]);
  if (fromMeta) return fromMeta;
  const headers = ex.requestInfo?.headers;
  if (!headers) return undefined;
  if (typeof (headers as { get?: unknown }).get === "function") {
    return shaped((headers as { get: (name: string) => string | null }).get(RESUME_HEADER));
  }
  if (typeof headers === "object") {
    const rec = headers as Record<string, unknown>;
    return shaped(rec[RESUME_HEADER] ?? rec[RESUME_HEADER.toLowerCase()]);
  }
  return undefined;
}

function errorResult(payload: Record<string, unknown>): ToolResult {
  return {
    isError: true,
    _meta: { "x402/error": payload },
    content: [{ type: "text", text: JSON.stringify(payload) }],
  };
}

/** One line of printable ASCII, cut short: what a reply or an error may put into a log line. */
function brief(text: string): string {
  return text.replace(/[^\x20-\x7e]+/g, " ").trim().slice(0, 160);
}

/** A Solana transaction signature as the facilitator names it, or "" for anything else. */
function signatureOf(value: unknown): string {
  return typeof value === "string" && /^[1-9A-HJ-NP-Za-km-z]{32,128}$/.test(value) ? value : "";
}

/** Object keys in sorted order, so one call's arguments always give one text. */
function canonicalJson(value: unknown, depth = 0): string {
  if (depth > 32 || value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return "[" + value.map((item) => canonicalJson(item, depth + 1)).join(",") + "]";
  const record = value as Record<string, unknown>;
  const fields = Object.keys(record)
    .filter((name) => record[name] !== undefined)
    .sort()
    .map((name) => JSON.stringify(name) + ":" + canonicalJson(record[name], depth + 1));
  return "{" + fields.join(",") + "}";
}

/**
 * Names one call: the tool and its arguments. An unresolved settlement is resumed only by the call that started it.
 * Once a payment is on chain anyone can read it there and present it, so the payment alone must not be enough; the
 * arguments are not on chain. They are not a secret either (some can be guessed, and a proxy sees them): this
 * narrows who can resume a settlement, it does not prove who paid. The resume code does the rest: see `readResumeCode`.
 */
export function paidCallId(name: string, args: unknown): string {
  return createHash("sha256").update(name).update("\n").update(canonicalJson(args)).digest("hex");
}

export type SettleOutcome =
  | { kind: "settled"; transaction: string; network: string }
  | { kind: "failed"; reason: string; transaction: string; /** For the log only. */ note?: string }
  | { kind: "unresolved"; reason: string; transaction: string };

/**
 * What one settle reply means. "failed" is only a definite answer that nothing was taken: HTTP 200 with
 * success false and a reason that is final. A request the facilitator turned down outright (HTTP 4xx) is final too,
 * but only for a payment's FIRST request: for a later one it says nothing about what the first one did. Everything
 * else (a busy or failing facilitator, "settlement_pending", a reply that cannot be read) leaves the outcome open.
 */
export function classifySettle(reply: SettleReply, first: boolean): SettleOutcome {
  const status = typeof reply.httpStatus === "number" ? reply.httpStatus : 200;
  const reason = typeof reply.errorReason === "string" ? reply.errorReason : "";
  const transaction = typeof reply.transaction === "string" ? reply.transaction : "";
  if (reply.success === true && status === 200) {
    return { kind: "settled", transaction, network: typeof reply.network === "string" ? reply.network : "" };
  }
  const open = reply.success === true || UNRESOLVED_REASONS.has(reason) || status >= 500 || [408, 409, 425, 429].includes(status);
  if (!open) {
    if (status === 200 && reply.success === false) return { kind: "failed", reason: reason || "SETTLEMENT_FAILED", transaction };
    if (first && status >= 400 && status < 500) return { kind: "failed", reason: reason || "SETTLEMENT_FAILED", transaction };
  }
  return { kind: "unresolved", reason: reason || (status === 200 ? "unreadable reply" : `HTTP ${status}`), transaction };
}

/**
 * One settle request with exactly `body`. Unlike x402's `useFacilitator().settle`, it gives the reply for every HTTP
 * status (the facilitator answers JSON on 4xx and 5xx too) and stops waiting after `timeoutMs`.
 */
export async function postSettle(url: string, body: string, timeoutMs: number, fetchFn: typeof fetch = fetch): Promise<SettleReply> {
  const res = await fetchFn(`${url}/settle`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    // Not JSON: the status alone decides.
  }
  const reply = data !== null && typeof data === "object" && !Array.isArray(data) ? (data as SettleReply) : {};
  return { ...reply, httpStatus: res.status };
}

/**
 * A settle request that failed before any connection was made (as Node's fetch reports it), so the facilitator
 * cannot have had it. Any other failure may have reached it.
 */
function neverSent(err: unknown): boolean {
  const code = (err as { cause?: { code?: unknown } } | null | undefined)?.cause?.code;
  return code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "UND_ERR_CONNECT_TIMEOUT";
}

/** A facilitator request that moves no money (verify, supported) was given up on after its time limit. */
class FacilitatorTimeout extends Error {}

/** `work`'s result, or a FacilitatorTimeout after `ms`. The request itself is not stopped; its late answer is dropped. */
function withTimeout<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new FacilitatorTimeout(`${what}: no answer in ${ms} ms`)), ms);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

/**
 * Build a paid-tool registrar. Create it once per process (it holds the claim
 * store), then bind it to each MCP server instance: `settleFirst(server)`.
 */
export function createSettleFirstPaidTools(cfg: SettleFirstConfig, deps: SettleFirstDeps = {}) {
  const recipient = cfg.recipient?.svm?.address;
  if (!recipient) throw new Error("settle-first x402: only an svm recipient is supported");
  const isTestnet = cfg.recipient.svm.isTestnet ?? false;
  const networks = SupportedSVMNetworks.filter((n) => n.includes("devnet") === isTestnet);
  const x402Version = cfg.version ?? 1;
  const now = deps.now ?? Date.now;
  const log = deps.log ?? ((line: string) => console.warn(line));
  const x402Client = useFacilitator(cfg.facilitator);
  const facilitator: FacilitatorClient = deps.facilitator ?? {
    verify: x402Client.verify,
    supported: x402Client.supported as FacilitatorClient["supported"],
    settleBody: (body, timeoutMs) => postSettle(cfg.facilitator.url, body, timeoutMs),
  };
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const verifyTimeoutMs = deps.verifyTimeoutMs ?? VERIFY_TIMEOUT_MS;
  const supportedTimeoutMs = deps.supportedTimeoutMs ?? SUPPORTED_TIMEOUT_MS;
  const claimsDir = deps.claimsDir ?? (process.env.X402_CLAIMS_DIR || path.join(os.homedir(), ".x402-claims"));
  const claims = new ClaimStore(claimsDir, now, log);
  (deps.info ?? ((line: string) => console.log(line)))(`[x402] settle-first paid tools; payment claims in ${claimsDir}`);

  /**
   * Asks the facilitator to settle `body` until it gives a final answer or the call's time for this is used up.
   * Every request carries the identical body: the facilitator settles a payment once and answers a repeat with the
   * recorded outcome. `again`: an earlier call already sent this body; `known` is the transaction the facilitator
   * named to that call, if it named one. `callDeadline`: when the call as a whole is to be answered.
   */
  async function resolveSettlement(body: string, again: boolean, known: string, callDeadline: number): Promise<SettleOutcome> {
    const budget = again ? SETTLE_AGAIN_BUDGET_MS : SETTLE_BUDGET_MS;
    const deadline = Math.min(now() + budget, callDeadline);
    let transaction = known;
    // Whether the facilitator may already have had this body. Until it may, an outright refusal is a final answer.
    let mayHaveArrived = again;
    for (let sent = 0; ; sent++) {
      // Never longer than the budget itself, whatever the clock does meanwhile.
      const timeoutMs = Math.min(budget, Math.max(SETTLE_REQUEST_MIN_MS, deadline - now()));
      let outcome: SettleOutcome;
      try {
        const reply = await facilitator.settleBody(body, timeoutMs);
        outcome = classifySettle(reply, !mayHaveArrived);
        mayHaveArrived = true;
      } catch (err) {
        if (!neverSent(err)) mayHaveArrived = true;
        outcome = { kind: "unresolved", reason: `no reply (${brief(String(err))})`, transaction: "" };
      }
      if (outcome.kind !== "unresolved") return outcome;
      transaction = outcome.transaction || transaction;
      const wait = SETTLE_ASK_AGAIN_DELAYS_MS[Math.min(sent, SETTLE_ASK_AGAIN_DELAYS_MS.length - 1)];
      if (sent + 1 >= SETTLE_MAX_REQUESTS || now() + wait >= deadline) {
        // No request of this call, the first one for this payment, ever reached the facilitator: nothing was sent,
        // so nothing can be taken. That is a failure, not an open outcome.
        if (!mayHaveArrived) return { kind: "failed", reason: "SETTLEMENT_FAILED", transaction: "", note: outcome.reason };
        return { ...outcome, transaction };
      }
      await sleep(wait);
    }
  }

  /**
   * Records how the settlement this call owns ended. The lock it needs is held by others for moments only; if it
   * stays taken (its holder died), the record is changed without it.
   */
  async function endClaim(key: string, owner: string, end: ClaimEnd): Promise<"done" | "lost" | "error"> {
    for (let tries = 0; tries < END_CLAIM_TRIES; tries++) {
      const ended = claims.end(key, owner, end);
      if (ended !== "busy") return ended;
      await sleep(END_CLAIM_WAIT_MS);
    }
    log("[x402] a claim's lock stayed taken; recording the settlement's outcome without it");
    const ended = claims.end(key, owner, end, true);
    return ended === "busy" ? "error" : ended;
  }

  /**
   * A call that may not resume a settlement costs the caller nothing, so it is logged once per claim and reason in
   * DENIED_LOG_EVERY_MS, not once per call. The memory of what was logged is bounded.
   */
  const deniedLogged = new Map<string, number>();
  function deniedLogDue(what: string): boolean {
    const last = deniedLogged.get(what);
    if (last !== undefined && now() - last < DENIED_LOG_EVERY_MS) return false;
    if (deniedLogged.size >= DENIED_LOG_MAX_ENTRIES) deniedLogged.clear();
    deniedLogged.set(what, now());
    return true;
  }

  let feePayerCache: { at: number; byNetwork: Map<string, string> } | null = null;
  let lastFeePayerRefresh = -Infinity;
  function refreshFeePayerSoon(): void {
    if (now() - lastFeePayerRefresh < FEE_PAYER_REFRESH_MIN_MS) return;
    lastFeePayerRefresh = now();
    feePayerCache = null;
  }
  let feePayersInFlight: Promise<Map<string, string>> | null = null;
  /** The facilitator's fee payer per network. Cached; concurrent calls share one supported() request. */
  function feePayers(): Promise<Map<string, string>> {
    if (feePayerCache && now() - feePayerCache.at < FEE_PAYER_TTL_MS) return Promise.resolve(feePayerCache.byNetwork);
    if (!feePayersInFlight) {
      const pending = (async () => {
        const { kinds } = await withTimeout(facilitator.supported(), supportedTimeoutMs, "supported");
        const byNetwork = new Map<string, string>();
        for (const kind of kinds) {
          const feePayer = kind.extra?.feePayer;
          if (kind.scheme === "exact" && typeof feePayer === "string" && !byNetwork.has(kind.network)) {
            byNetwork.set(kind.network, feePayer);
          }
        }
        feePayerCache = { at: now(), byNetwork };
        return byNetwork;
      })();
      feePayersInFlight = pending;
      const clear = () => {
        if (feePayersInFlight === pending) feePayersInFlight = null;
      };
      pending.then(clear, clear);
    }
    return feePayersInFlight;
  }

  async function buildRequirements(name: string, description: string, price: Price): Promise<PaymentRequirements[]> {
    let payers: Map<string, string>;
    try {
      payers = await feePayers();
    } catch {
      return [];
    }
    const reqs: PaymentRequirements[] = [];
    for (const network of networks) {
      const atomic = processPriceToAtomicAmount(price, network);
      const feePayer = payers.get(network);
      if ("error" in atomic || !feePayer) continue;
      reqs.push({
        scheme: "exact",
        network: network as Network,
        maxAmountRequired: atomic.maxAmountRequired,
        payTo: recipient,
        asset: String(atomic.asset.address),
        maxTimeoutSeconds: 300,
        resource: `mcp://${name}`,
        mimeType: "application/json",
        description,
        extra: { feePayer },
      });
    }
    return reqs;
  }

  function annotationsFor(price: Price): Record<string, unknown> {
    const paymentNetworks = [];
    for (const network of networks) {
      const atomic = processPriceToAtomicAmount(price, network);
      if ("error" in atomic) continue;
      const asset = atomic.asset as { address: string; symbol?: string; decimals?: number };
      paymentNetworks.push({
        network,
        recipient,
        maxAmountRequired: atomic.maxAmountRequired.toString(),
        asset: { address: asset.address, symbol: asset.symbol, decimals: asset.decimals },
        type: "svm",
      });
    }
    return { paymentHint: true, paymentPriceUSD: price, paymentNetworks, paymentVersion: x402Version };
  }

  return function bind(server: object) {
    const registrar = server as ToolRegistrar;
    return function paidTool<A>(
      name: string,
      description: string,
      price: Price,
      paramsSchema: Record<string, unknown>,
      annotations: Record<string, unknown>,
      cb: (args: A, extra: unknown) => Promise<ToolResult>,
      options: PaidToolOptions<A> = {},
    ): unknown {
      return registrar.tool(name, description, paramsSchema, { ...annotations, ...annotationsFor(price) }, async (args: A, extra: unknown) => {
        const callDeadline = now() + CALL_BUDGET_MS;
        if (options.precheck) {
          const problem = await options.precheck(args);
          if (problem) return { isError: true, content: [{ type: "text", text: `Error: ${problem}` }] };
        }

        const accepts = await buildRequirements(name, description, price);
        if (!accepts.length) return errorResult({ x402Version, error: "PRICE_COMPUTE_FAILED" });
        const paymentRequired = (reason = "PAYMENT_REQUIRED", fields: Record<string, unknown> = {}) =>
          errorResult({ x402Version, error: reason, accepts, resume: RESUME_HINT, ...fields });

        const token = readPaymentToken(extra);
        if (!token) return paymentRequired();
        if (token.length > MAX_PAYMENT_TOKEN_LENGTH) return paymentRequired("INVALID_PAYMENT");
        let decoded: PaymentPayload;
        try {
          decoded = decodePayment(token);
          decoded.x402Version = x402Version;
        } catch {
          return paymentRequired("INVALID_PAYMENT");
        }
        const selected = findMatchingPaymentRequirements(accepts, decoded) as PaymentRequirements | undefined;
        if (!selected) return paymentRequired("UNABLE_TO_MATCH_PAYMENT_REQUIREMENTS");
        const key = paymentClaimKey(decoded);
        const payer = paymentAuthority(decoded);
        // The facilitator's published fee payer signs whatever it is asked to, so it is never a payer identity.
        const feePayer = (selected.extra as { feePayer?: unknown } | undefined)?.feePayer;
        if (!key || !payer || payer === feePayer) return paymentRequired("INVALID_PAYMENT");

        const call = paidCallId(name, args);
        // The resume code this call presents: the code of an unresolved settlement it wants resumed, or, with a
        // payment's first presentation, the code the caller chooses for it.
        const resumeCode = readResumeCode(extra);
        /**
         * The outcome of the payment is not known. No `accepts`: a client must not be led to pay a second time.
         * `resumeCode`: only from a call that owns, or owned, the payment's settlement.
         */
        const unresolved = (transaction: string, message: string, retryAfterSeconds = UNRESOLVED_RETRY_SECONDS, resumeCode?: string): ToolResult =>
          errorResult({
            x402Version,
            error: SETTLEMENT_UNRESOLVED,
            message,
            ...(signatureOf(transaction) ? { transaction } : {}),
            retryAfterSeconds,
            ...(resumeCode ? { resumeCode } : {}),
          });
        /** The claim directory cannot be used, so this call sends nothing for settlement. No `accepts` either. */
        const unavailable = (): ToolResult => errorResult({ x402Version, error: "PAYMENT_CLAIM_UNAVAILABLE", message: CLAIM_UNAVAILABLE_MESSAGE });
        /**
         * A claim this call could not hand on stays marked as its settlement in progress, and can be resumed only
         * once that mark is SETTLING_STALE_MS old: the caller is told to wait that long.
         */
        const STUCK_RETRY_SECONDS = SETTLING_STALE_MS / 1000;

        /**
         * Settles the payment whose settlement this call owns, then runs the tool. `paid`: an earlier call already
         * had the facilitator's answer that the payment settled, so it is not asked again. Every answer here that
         * leaves the outcome open carries the payment's resume code, where the payment has one.
         */
        const settleAndRun = async ({ owner, code }: OwnedSettlement, body: string, again: boolean, known = "", paid?: PaidMark): Promise<ToolResult> => {
          const open = (transaction: string, message = unresolvedMessage(code !== undefined), retryAfterSeconds = UNRESOLVED_RETRY_SECONDS): ToolResult =>
            unresolved(transaction, message, retryAfterSeconds, code);
          const outcome: SettleOutcome = paid ? { kind: "settled", transaction: paid.tx, network: paid.network } : await resolveSettlement(body, again, known, callDeadline);
          const tx = brief(outcome.transaction) || "-";
          if (outcome.kind === "failed") {
            const ended = await endClaim(key, owner, { s: "released" });
            const note = outcome.note ? ` (${brief(outcome.note)})` : "";
            log(`[x402] ${name}: settle failed, tool not run: reason=${brief(outcome.reason)}${note} tx=${tx} payer=${payer}`);
            return ended === "lost" ? open(outcome.transaction) : paymentRequired(outcome.reason);
          }
          if (outcome.kind === "unresolved") {
            const kept = await endClaim(key, owner, { s: "unresolved", tx: signatureOf(outcome.transaction) });
            log(`[x402] ${name}: settlement unresolved, claim kept, tool not run: reason=${brief(outcome.reason)} tx=${tx} payer=${payer}`);
            return open(outcome.transaction, undefined, kept === "error" ? STUCK_RETRY_SECONDS : UNRESOLVED_RETRY_SECONDS);
          }
          const recorded = await endClaim(key, owner, { s: "settled", tx: outcome.transaction });
          if (recorded === "lost") {
            log(`[x402] ${name}: settled, but this call no longer owns the settlement (a later call took it over), tool not run here: tx=${tx} payer=${payer}`);
            return open(outcome.transaction);
          }
          if (recorded === "error") {
            // Run now and the claim would still read as a settlement in progress: the same call could resume it
            // later and run the tool a second time. So the tool waits for a call that can record the payment. The
            // claim is handed on as unresolved, marked as paid, if that much can be written: the same call can then
            // resume it at once, and needs no second answer from the facilitator.
            const paidMark = { tx: outcome.transaction, network: outcome.network };
            const kept = await endClaim(key, owner, { s: "unresolved", tx: signatureOf(outcome.transaction), paid: paidMark });
            log(`[x402] ${name}: settled (paid), but the claim could not be marked settled, tool not run: tx=${tx} payer=${payer}`);
            return open(outcome.transaction, notRecordedMessage(code !== undefined), kept === "done" ? UNRESOLVED_RETRY_SECONDS : STUCK_RETRY_SECONDS);
          }

          const settlement: X402Settlement = {
            payer,
            transaction: outcome.transaction,
            network: outcome.network,
          };
          let result: ToolResult;
          let failed = false;
          try {
            result = await cb(args, { ...(extra as Record<string, unknown>), x402Settlement: settlement });
            if (!result || typeof result !== "object") {
              result = { isError: true, content: [{ type: "text", text: "Tool execution failed: no result" }] };
            }
            failed = result.isError === true;
          } catch (err) {
            failed = true;
            result = { isError: true, content: [{ type: "text", text: `Tool execution failed: ${String(err)}` }] };
          }
          result._meta = { ...(result._meta ?? {}), "x402/payment-response": { success: true, ...settlement } };
          if (failed) {
            log(`[x402] ${name}: failed after settlement (paid) payer=${payer} tx=${settlement.transaction}`);
          }
          return result;
        };

        let claimed: boolean;
        try {
          claimed = claims.tryClaim(key, call);
        } catch (err) {
          log(`[x402] ${name}: payment claim store unavailable, payment refused unpaid: ${String(err)}`);
          return unavailable();
        }
        if (!claimed) {
          // The payment is claimed. For any other call it is in use or used up. For this same call it is either
          // still at work (no new payment is offered while it may yet be taken) or was left unresolved: resume it,
          // if the caller holds the payment's resume code.
          const denied = (): ToolResult => {
            const why = resumeCode ? "wrong resume code" : "no resume code";
            if (deniedLogDue(`${key}:${why}`)) log(`[x402] ${name}: an unresolved settlement was not resumed: ${why} payer=${payer}`);
            return unresolved("", RESUME_CODE_MESSAGE);
          };
          const held = claims.heldFor(key, call, resumeCode);
          if (held === "used") return paymentRequired("PAYMENT_ALREADY_USED");
          if (held === "open") return unresolved("", IN_PROGRESS_MESSAGE);
          if (held === "unknown") return unresolved("", CLAIM_UNREADABLE_MESSAGE);
          if (held === "denied") return denied();
          if (options.preflight) {
            // The payment may already be taken, so nothing is promised here: the settlement stays as it is.
            let notReady: string | null;
            try {
              notReady = await options.preflight(args);
            } catch (err) {
              log(`[x402] ${name}: preflight check threw, unresolved settlement left as it is: ${String(err)} payer=${payer}`);
              notReady = PREFLIGHT_FAILED;
            }
            if (notReady) {
              log(`[x402] ${name}: not ready, unresolved settlement left as it is, tool not run: ${notReady} payer=${payer}`);
              return unresolved("", NOT_READY_MESSAGE);
            }
          }
          const taken = claims.takeOver(key, call, resumeCode);
          if (taken === "used") return paymentRequired("PAYMENT_ALREADY_USED");
          if (taken === "open") return unresolved("", IN_PROGRESS_MESSAGE);
          if (taken === "denied") return denied();
          if (taken.paid) log(`[x402] ${name}: resuming a settled payment whose call has not run: tx=${brief(taken.paid.tx) || "-"} payer=${payer}`);
          else log(`[x402] ${name}: asking again about an unresolved settlement: tx=${brief(taken.tx) || "-"} payer=${payer}`);
          return settleAndRun(taken, taken.body, true, taken.tx, taken.paid);
        }

        let verified: VerifyResponse;
        try {
          verified = await withTimeout(facilitator.verify(decoded, selected), verifyTimeoutMs, "verify");
        } catch (err) {
          claims.release(key);
          refreshFeePayerSoon();
          if (err instanceof FacilitatorTimeout) log(`[x402] ${name}: ${err.message}, payment refused unpaid (nothing was sent for settlement) payer=${payer}`);
          return paymentRequired("VERIFY_FAILED");
        }
        if (!verified.isValid) {
          claims.release(key);
          refreshFeePayerSoon();
          return paymentRequired(verified.invalidReason ?? "INVALID_PAYMENT", { payer: verified.payer });
        }

        if (options.preflight) {
          let notReady: string | null;
          try {
            notReady = await options.preflight(args);
          } catch (err) {
            log(`[x402] ${name}: preflight check threw, payment not settled: ${String(err)} payer=${payer}`);
            notReady = PREFLIGHT_FAILED;
          }
          if (notReady) {
            claims.release(key);
            log(`[x402] ${name}: not ready, payment not settled, tool not run: ${notReady} payer=${payer}`);
            return { isError: true, content: [{ type: "text", text: `Error: ${notReady}` }] };
          }
        }

        // The exact request is recorded before it is sent, so the settlement can be resumed whatever happens to this call.
        const body = JSON.stringify({
          x402Version: decoded.x402Version,
          paymentPayload: toJsonSafe(decoded),
          paymentRequirements: toJsonSafe(selected),
        });
        const owned = claims.markSettling(key, call, body, resumeCode);
        if (!owned) {
          claims.release(key);
          log(`[x402] ${name}: payment claim store unavailable, payment not sent for settlement, tool not run payer=${payer}`);
          return unavailable();
        }
        return settleAndRun(owned, body, false);
      });
    };
  };
}
