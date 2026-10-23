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
 * A payment that fails to settle releases its claim and never runs the tool.
 * Claims are marker files in one directory shared by every server that takes
 * the same wallet's payments (default ~/.x402-claims), so one payment sent to
 * several servers at once runs one tool, and a replay after a restart is
 * refused. A settled claim is kept for 24 hours. A tool that fails after
 * settlement has been paid for: the result says so (x402/payment-response) and
 * the server logs it.
 *
 * Requirement building and payment-token parsing follow mcpay 0.1.17
 * (MIT License, Copyright (c) MCPay). Solana ("svm") recipients only.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { decodePayment } from "x402/schemes";
import { findMatchingPaymentRequirements, processPriceToAtomicAmount } from "x402/shared";
import { SupportedSVMNetworks } from "x402/types";
import type { PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse } from "x402/types";
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

export interface FacilitatorClient {
  verify: (payload: PaymentPayload, requirements: PaymentRequirements) => Promise<VerifyResponse>;
  settle: (payload: PaymentPayload, requirements: PaymentRequirements) => Promise<SettleResponse>;
  supported: () => Promise<{ kinds: Array<{ scheme: string; network: string; extra?: Record<string, unknown> }> }>;
}

/** The MCP server's `tool(name, description, paramsSchema, annotations, cb)` overload, as mcpay calls it. */
type ToolRegistrar = { tool: (...args: unknown[]) => unknown };

export interface PaidToolOptions<A> {
  /** Cheap input checks that run before any payment is asked for or taken. Return a message to refuse the call. */
  precheck?: (args: A) => Promise<string | null> | string | null;
}

export interface SettleFirstDeps {
  facilitator?: FacilitatorClient;
  /** Claim directory shared by every server paid to the same wallet. Default: X402_CLAIMS_DIR or ~/.x402-claims */
  claimsDir?: string;
  now?: () => number;
  log?: (line: string) => void;
  /** Startup information (the claim directory in use). Default: console.log */
  info?: (line: string) => void;
}

const CLAIM_TTL_MS = 24 * 60 * 60 * 1000;
const PRUNE_EVERY_MS = 10 * 60 * 1000;
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

  /** Take the claim; false when any process already holds it. Throws when the directory cannot be written. */
  tryClaim(key: string): boolean {
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
      fs.writeSync(fd, JSON.stringify({ s: "pending", t: this.now() }));
    } finally {
      fs.closeSync(fd);
    }
    return true;
  }

  markSettled(key: string, transaction: string): void {
    try {
      fs.writeFileSync(this.file(key), JSON.stringify({ s: "settled", t: this.now(), tx: transaction }), { mode: 0o600 });
    } catch (err) {
      this.log(`[x402] could not mark claim settled (claim still held): ${String(err)}`);
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

  /** Delete claims older than 24 hours; their payments can no longer settle. */
  private pruneOccasionally(): void {
    const now = this.now();
    if (now - this.lastPrune < PRUNE_EVERY_MS) return;
    this.lastPrune = now;
    try {
      for (const name of fs.readdirSync(this.dir)) {
        if (!name.endsWith(".claim")) continue;
        const file = path.join(this.dir, name);
        try {
          if (now - fs.statSync(file).mtimeMs > CLAIM_TTL_MS) fs.unlinkSync(file);
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

/** The message bytes of a base64 Solana wire transaction: everything after the signature section. */
function wireMessage(transaction: unknown): Buffer | null {
  if (typeof transaction !== "string") return null;
  const bytes = Buffer.from(transaction, "base64");
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

const TOKEN_PROGRAMS = new Set([
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022
]);
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

/**
 * The paying wallet: the signer that authorizes the payment's one token
 * TransferChecked, read from the signed transaction. The facilitator's reply
 * is not used for this, because x402's reference facilitator reports its own
 * fee payer as "payer". Returns null unless the message (legacy or v0) has
 * exactly one TransferChecked and its authority is a signer.
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
    if (programIndex >= keys.value || !TOKEN_PROGRAMS.has(base58(key(programIndex)))) continue;
    if (dataBytes[0] !== TRANSFER_CHECKED) continue;
    transfers++;
    if (accountIndexes.length < 4) return null;
    authority = accountIndexes[3];
  }
  if (transfers !== 1 || authority < 0 || authority >= signerCount || authority >= keys.value) return null;
  return base58(key(authority));
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

function errorResult(payload: Record<string, unknown>): ToolResult {
  return {
    isError: true,
    _meta: { "x402/error": payload },
    content: [{ type: "text", text: JSON.stringify(payload) }],
  };
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
  const facilitator: FacilitatorClient = deps.facilitator ?? (useFacilitator(cfg.facilitator) as FacilitatorClient);
  const claimsDir = deps.claimsDir ?? (process.env.X402_CLAIMS_DIR || path.join(os.homedir(), ".x402-claims"));
  const claims = new ClaimStore(claimsDir, now, log);
  (deps.info ?? ((line: string) => console.log(line)))(`[x402] settle-first paid tools; payment claims in ${claimsDir}`);

  let feePayerCache: { at: number; byNetwork: Map<string, string> } | null = null;
  let lastFeePayerRefresh = -Infinity;
  function refreshFeePayerSoon(): void {
    if (now() - lastFeePayerRefresh < FEE_PAYER_REFRESH_MIN_MS) return;
    lastFeePayerRefresh = now();
    feePayerCache = null;
  }
  async function feePayers(): Promise<Map<string, string>> {
    if (feePayerCache && now() - feePayerCache.at < FEE_PAYER_TTL_MS) return feePayerCache.byNetwork;
    const { kinds } = await facilitator.supported();
    const byNetwork = new Map<string, string>();
    for (const kind of kinds) {
      const feePayer = kind.extra?.feePayer;
      if (kind.scheme === "exact" && typeof feePayer === "string" && !byNetwork.has(kind.network)) {
        byNetwork.set(kind.network, feePayer);
      }
    }
    feePayerCache = { at: now(), byNetwork };
    return byNetwork;
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
        if (options.precheck) {
          const problem = await options.precheck(args);
          if (problem) return { isError: true, content: [{ type: "text", text: `Error: ${problem}` }] };
        }

        const accepts = await buildRequirements(name, description, price);
        if (!accepts.length) return errorResult({ x402Version, error: "PRICE_COMPUTE_FAILED" });
        const paymentRequired = (reason = "PAYMENT_REQUIRED", fields: Record<string, unknown> = {}) =>
          errorResult({ x402Version, error: reason, accepts, ...fields });

        const token = readPaymentToken(extra);
        if (!token) return paymentRequired();
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
        if (!key || !payer) return paymentRequired("INVALID_PAYMENT");

        let claimed: boolean;
        try {
          claimed = claims.tryClaim(key);
        } catch (err) {
          log(`[x402] ${name}: payment claim store unavailable, payment refused unpaid: ${String(err)}`);
          return paymentRequired("PAYMENT_CLAIM_UNAVAILABLE");
        }
        if (!claimed) return paymentRequired("PAYMENT_ALREADY_USED");

        let verified: VerifyResponse;
        try {
          verified = await facilitator.verify(decoded, selected);
        } catch {
          claims.release(key);
          refreshFeePayerSoon();
          return paymentRequired("VERIFY_FAILED");
        }
        if (!verified.isValid) {
          claims.release(key);
          refreshFeePayerSoon();
          return paymentRequired(verified.invalidReason ?? "INVALID_PAYMENT", { payer: verified.payer });
        }

        let settled: SettleResponse;
        try {
          settled = await facilitator.settle(decoded, selected);
        } catch (err) {
          claims.release(key);
          log(`[x402] ${name}: settle request failed, tool not run: ${String(err)} payer=${payer}`);
          return paymentRequired("SETTLEMENT_FAILED");
        }
        if (!settled.success) {
          claims.release(key);
          log(
            `[x402] ${name}: settle failed, tool not run: reason=${settled.errorReason ?? "?"} tx=${settled.transaction || "-"} payer=${payer}`,
          );
          return paymentRequired(settled.errorReason ?? "SETTLEMENT_FAILED");
        }
        claims.markSettled(key, settled.transaction);

        const settlement: X402Settlement = {
          payer,
          transaction: settled.transaction,
          network: settled.network,
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
      });
    };
  };
}
