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
 * A settled payment keeps its claim for 24 hours, on disk, so a replay after a
 * restart is refused too. A tool that fails after settlement has been paid
 * for: the result says so (x402/payment-response) and the server logs it.
 *
 * Requirement building and payment-token parsing follow mcpay 0.1.17
 * (MIT License, Copyright (c) MCPay). Solana ("svm") recipients only.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
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
  payer?: string;
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
  /** Cheap input checks that run before any payment is taken. Return a message to refuse the call unpaid. */
  precheck?: (args: A) => Promise<string | null> | string | null;
}

export interface SettleFirstDeps {
  facilitator?: FacilitatorClient;
  /** Claim file path; null keeps claims in memory only. Default: X402_CLAIMS_FILE or ./.x402-claims.jsonl */
  claimsFile?: string | null;
  now?: () => number;
  log?: (line: string) => void;
}

const CLAIM_TTL_MS = 24 * 60 * 60 * 1000;
const FEE_PAYER_TTL_MS = 10 * 60 * 1000;

type ClaimState = "pending" | "settled";

/** Single-use payment claims: in memory, mirrored to an append-only JSONL file. */
export class ClaimStore {
  private readonly claims = new Map<string, { state: ClaimState; at: number }>();
  private writesSinceCompact = 0;

  constructor(
    private readonly file: string | null,
    private readonly now: () => number,
    private readonly log: (line: string) => void,
  ) {
    this.load();
  }

  /** Atomically take the claim; false when the payment is pending or already settled. */
  tryClaim(key: string): boolean {
    this.prune();
    if (this.claims.has(key)) return false;
    this.set(key, "pending");
    return true;
  }

  markSettled(key: string): void {
    this.set(key, "settled");
  }

  release(key: string): void {
    if (!this.claims.delete(key)) return;
    this.append({ k: key, s: "released", t: this.now() });
  }

  has(key: string): boolean {
    this.prune();
    return this.claims.has(key);
  }

  private set(key: string, state: ClaimState): void {
    const at = this.now();
    this.claims.set(key, { state, at });
    this.append({ k: key, s: state, t: at });
  }

  private prune(): void {
    const cutoff = this.now() - CLAIM_TTL_MS;
    for (const [key, entry] of this.claims) {
      if (entry.at < cutoff) this.claims.delete(key);
    }
  }

  private load(): void {
    if (!this.file || !fs.existsSync(this.file)) return;
    const cutoff = this.now() - CLAIM_TTL_MS;
    try {
      for (const line of fs.readFileSync(this.file, "utf8").split("\n")) {
        if (!line.trim()) continue;
        let rec: { k?: unknown; s?: unknown; t?: unknown };
        try {
          rec = JSON.parse(line) as { k?: unknown; s?: unknown; t?: unknown };
        } catch {
          continue;
        }
        if (typeof rec.k !== "string" || typeof rec.t !== "number") continue;
        if (rec.s === "released") this.claims.delete(rec.k);
        else if (rec.t >= cutoff && (rec.s === "pending" || rec.s === "settled")) {
          this.claims.set(rec.k, { state: rec.s, at: rec.t });
        }
      }
      this.compact();
    } catch (err) {
      this.log(`[x402] could not load payment claims from ${this.file}: ${String(err)}`);
    }
  }

  private append(rec: { k: string; s: string; t: number }): void {
    if (!this.file) return;
    try {
      fs.appendFileSync(this.file, JSON.stringify(rec) + "\n", { mode: 0o600 });
      if (++this.writesSinceCompact >= 1000) this.compact();
    } catch (err) {
      this.log(`[x402] could not persist payment claim (kept in memory): ${String(err)}`);
    }
  }

  private compact(): void {
    if (!this.file) return;
    this.prune();
    const tmp = `${this.file}.tmp`;
    const lines = [...this.claims].map(([k, v]) => JSON.stringify({ k, s: v.state, t: v.at }) + "\n").join("");
    fs.writeFileSync(tmp, lines, { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    this.writesSinceCompact = 0;
  }
}

/**
 * Claim key for an "exact" Solana payment: SHA-256 of the transaction message
 * (the bytes after the signature section). The payer's signature covers
 * exactly these bytes, so every encoding of a payment that could settle has the
 * same key. Returns null for anything else.
 */
export function paymentClaimKey(payment: PaymentPayload): string | null {
  const payload = payment.payload as { transaction?: unknown };
  if (typeof payload.transaction !== "string") return null;
  const bytes = Buffer.from(payload.transaction, "base64");
  // Solana wire format: compact-u16 signature count, 64-byte signatures, then the message.
  let count = 0;
  let offset = 0;
  for (let shift = 0; shift <= 14; shift += 7) {
    if (offset >= bytes.length) return null;
    const byte = bytes[offset++];
    count |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    if (shift === 14) return null;
  }
  const messageStart = offset + count * 64;
  if (count === 0 || messageStart >= bytes.length) return null;
  return "svm:" + createHash("sha256").update(bytes.subarray(messageStart)).digest("hex");
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
  const claimsFile =
    deps.claimsFile === undefined
      ? process.env.X402_CLAIMS_FILE || path.join(process.cwd(), ".x402-claims.jsonl")
      : deps.claimsFile;
  const claims = new ClaimStore(claimsFile, now, log);

  let feePayerCache: { at: number; byNetwork: Map<string, string> } | null = null;
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
        if (!key) return paymentRequired("INVALID_PAYMENT");

        if (options.precheck) {
          const problem = await options.precheck(args);
          if (problem) return { isError: true, content: [{ type: "text", text: `Error: ${problem}` }] };
        }

        if (!claims.tryClaim(key)) return paymentRequired("PAYMENT_ALREADY_USED");

        let verified: VerifyResponse;
        try {
          verified = await facilitator.verify(decoded, selected);
        } catch {
          claims.release(key);
          return paymentRequired("VERIFY_FAILED");
        }
        if (!verified.isValid) {
          claims.release(key);
          return paymentRequired(verified.invalidReason ?? "INVALID_PAYMENT", { payer: verified.payer });
        }

        let settled: SettleResponse;
        try {
          settled = await facilitator.settle(decoded, selected);
        } catch (err) {
          claims.release(key);
          log(`[x402] ${name}: settle request failed, tool not run: ${String(err)}`);
          return paymentRequired("SETTLEMENT_FAILED");
        }
        if (!settled.success) {
          claims.release(key);
          return paymentRequired(settled.errorReason ?? "SETTLEMENT_FAILED");
        }
        claims.markSettled(key);

        const settlement: X402Settlement = {
          payer: settled.payer ?? verified.payer,
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
          log(`[x402] ${name}: failed after settlement (paid) payer=${settlement.payer ?? "?"} tx=${settlement.transaction}`);
        }
        return result;
      });
    };
  };
}
