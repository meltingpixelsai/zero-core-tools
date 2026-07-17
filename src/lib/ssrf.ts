import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * SSRF protection for the URL-consuming paid tools (scrape_url,
 * screenshot_url, extract_structured_data). These drive a Playwright browser
 * to a URL supplied by an external, paying caller — `z.string().url()` only
 * checks syntax, so without this guard an agent could reach the cloud
 * metadata endpoint (169.254.169.254), loopback services (127.0.0.1:4000),
 * or any RFC-1918 host behind the server.
 *
 * The guard runs in two places (see browser.ts):
 *   1. Before navigation — assertUrlSafe() gives a clean error and fails fast.
 *   2. On every browser request via a route interceptor — closes redirect-to-
 *      internal and internal-subresource vectors that a pre-check can't see.
 *
 * Resolution is delegated to the OS resolver (getaddrinfo), the same family
 * Chromium uses, so decimal/octal/hex IP encodings (http://2130706433) are
 * normalized to their real address before the range check — matching what the
 * browser will actually connect to. The residual is classic DNS-rebinding
 * (our lookup vs the browser's connect are two separate resolutions); the
 * complete defense for that is an egress network policy, tracked separately.
 */

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

// Only these schemes reach the browser. new URL() (and Zod's .url()) happily
// accept file:, ftp:, gopher:, etc.
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

// IPv4 CIDRs that must never be reachable. Covers loopback, RFC-1918 private,
// link-local (incl. the 169.254.169.254 metadata address), CGNAT, benchmark,
// documentation, multicast, and reserved space.
const BLOCKED_V4_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function v4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const octet of parts) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const v = Number(octet);
    if (v > 255) return null;
    n = (n * 256 + v) >>> 0;
  }
  return n >>> 0;
}

function isBlockedV4(ip: string): boolean {
  const n = v4ToInt(ip);
  if (n === null) return true; // unparseable in a v4 context → treat as unsafe
  for (const [base, bits] of BLOCKED_V4_CIDRS) {
    const b = v4ToInt(base);
    if (b === null) continue;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((n & mask) >>> 0 === (b & mask) >>> 0) return true;
  }
  return false;
}

function isBlockedV6(ip: string): boolean {
  const a = ip.toLowerCase();
  if (a === "::1" || a === "::") return true; // loopback, unspecified
  if (/^fe[89ab]/.test(a)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(a)) return true; // fc00::/7 unique-local
  // IPv4-mapped (::ffff:a.b.c.d) — validate the embedded v4.
  const mapped = a.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return isBlockedV4(mapped[1]);
  return false;
}

/** True if the given IP literal is in loopback/private/link-local/reserved space. */
export function isBlockedIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isBlockedV4(ip);
  if (family === 6) return isBlockedV6(ip);
  return true; // not a recognizable IP literal → unsafe
}

/** Strips the [] wrapper Node puts around IPv6 hostnames. */
function bareHost(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

/**
 * Throws SsrfError unless `rawUrl` is a http(s) URL whose host resolves
 * exclusively to public addresses. Every resolved address must pass — a host
 * with even one private answer is rejected (a DNS-rebinding record could list
 * both).
 */
export async function assertUrlSafe(rawUrl: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfError("Invalid URL");
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new SsrfError(`Blocked URL scheme: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new SsrfError("URLs with embedded credentials are not allowed");
  }

  const host = bareHost(url.hostname);
  if (!host) throw new SsrfError("URL has no host");

  // Fast path: literal IP in the URL — check before any DNS.
  if (isIP(host)) {
    if (isBlockedIp(host)) {
      throw new SsrfError(`Blocked private/internal address: ${host}`);
    }
    return;
  }

  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw new SsrfError(`Could not resolve host: ${host}`);
  }
  if (addresses.length === 0) {
    throw new SsrfError(`Host did not resolve: ${host}`);
  }
  for (const { address } of addresses) {
    if (isBlockedIp(address)) {
      throw new SsrfError(`Host ${host} resolves to a private/internal address: ${address}`);
    }
  }
}

/** Non-throwing form for the per-request route interceptor. */
export async function isUrlSafe(rawUrl: string): Promise<boolean> {
  try {
    await assertUrlSafe(rawUrl);
    return true;
  } catch {
    return false;
  }
}
