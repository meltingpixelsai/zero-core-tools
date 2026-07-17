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

function isBlockedV4Int(n: number): boolean {
  for (const [base, bits] of BLOCKED_V4_CIDRS) {
    const b = v4ToInt(base);
    if (b === null) continue;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if (((n & mask) >>> 0) === ((b & mask) >>> 0)) return true;
  }
  return false;
}

function isBlockedV4(ip: string): boolean {
  const n = v4ToInt(ip);
  if (n === null) return true; // unparseable in a v4 context → treat as unsafe
  return isBlockedV4Int(n);
}

/** Blocks an embedded-IPv4 carried in two 16-bit IPv6 hextets. */
function isBlockedEmbeddedV4(hi: number, lo: number): boolean {
  return isBlockedV4Int((((hi & 0xffff) << 16) | (lo & 0xffff)) >>> 0);
}

/**
 * Expands an IPv6 literal (already validated by net.isIP) to its 8 hextets,
 * resolving `::` compression and a trailing embedded dotted-quad. Returns null
 * only on a malformed input (treated as unsafe by the caller).
 */
function v6Hextets(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone); // strip scope id (fe80::1%eth0)

  // Fold a trailing embedded IPv4 (e.g. ::ffff:1.2.3.4) into two hextets so
  // the rest of the parser only deals with hex groups.
  if (s.includes(".")) {
    const colon = s.lastIndexOf(":");
    if (colon < 0) return null;
    const v4 = v4ToInt(s.slice(colon + 1));
    if (v4 === null) return null;
    s = s.slice(0, colon + 1) +
      ((v4 >>> 16) & 0xffff).toString(16) + ":" + (v4 & 0xffff).toString(16);
  }

  const parseGroups = (part: string): number[] =>
    part === "" ? [] : part.split(":").map((h) => parseInt(h, 16));

  const halves = s.split("::");
  if (halves.length > 2) return null;

  if (halves.length === 1) {
    const groups = parseGroups(s);
    return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : null;
  }

  const head = parseGroups(halves[0]);
  const tail = parseGroups(halves[1]);
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null; // :: must stand for at least one 0 group
  const full = [...head, ...Array<number>(missing).fill(0), ...tail];
  return full.length === 8 && full.every((g) => g >= 0 && g <= 0xffff) ? full : null;
}

function isBlockedV6(ip: string): boolean {
  const h = v6Hextets(ip);
  if (!h) return true; // malformed → unsafe

  if (h.every((g) => g === 0)) return true; // :: unspecified
  if (h.slice(0, 7).every((g) => g === 0) && h[7] === 1) return true; // ::1 loopback
  if ((h[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((h[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((h[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 deprecated site-local

  // Every form that embeds an IPv4 address must have that v4 range-checked —
  // new URL() serializes IPv4-mapped to hex (::ffff:7f00:1), so a dotted-only
  // match is dead code on the real path (the ::ffff:169.254.169.254 metadata
  // bypass). Decode the embedded v4 by structure instead.
  const first6Zero = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0;
  if (first6Zero && h[5] === 0xffff) return isBlockedEmbeddedV4(h[6], h[7]); // ::ffff:0:0/96 mapped
  if (first6Zero && h[5] === 0) return isBlockedEmbeddedV4(h[6], h[7]); // ::/96 IPv4-compatible (deprecated)
  if (h[0] === 0x0064 && h[1] === 0xff9b) return isBlockedEmbeddedV4(h[6], h[7]); // 64:ff9b::/96 NAT64
  if (h[0] === 0x2002) return isBlockedEmbeddedV4(h[1], h[2]); // 2002::/16 6to4
  if (h[0] === 0x2001 && h[1] === 0x0000) {
    return isBlockedEmbeddedV4(h[6] ^ 0xffff, h[7] ^ 0xffff); // 2001:0000::/32 Teredo (client v4 is XOR-obfuscated)
  }
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

// The resolver is indirected so tests can exercise the DNS allow/deny loop
// hermetically (real hostnames would need the network). Production always
// uses getaddrinfo via dns/promises.lookup.
export type ResolveFn = (host: string) => Promise<Array<{ address: string }>>;
const defaultResolve: ResolveFn = (host) => lookup(host, { all: true, verbatim: true });
let resolveHost: ResolveFn = defaultResolve;

/** Test-only: override (or reset with null) the DNS resolver. */
export function __setResolverForTests(fn: ResolveFn | null): void {
  resolveHost = fn ?? defaultResolve;
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
    addresses = await resolveHost(host);
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
