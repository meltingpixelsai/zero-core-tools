import { test } from "node:test";
import assert from "node:assert/strict";
import { __setResolverForTests, assertUrlSafe, isBlockedIp, isUrlSafe, SsrfError } from "./ssrf.js";

// All cases here resolve locally (literal IPs, numeric encodings, localhost) —
// the suite makes no outbound network call.

test("isBlockedIp flags loopback/private/link-local/reserved v4", () => {
  for (const ip of [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.5.9",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.64.0.1", // CGNAT
    "0.0.0.0",
    "192.0.2.10",
    "224.0.0.1",
    "255.255.255.255",
  ]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test("isBlockedIp flags loopback/ULA/link-local/site-local v6", () => {
  for (const ip of ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1"]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test("isBlockedIp flags embedded-IPv4 v6 in every form (mapped/compat/NAT64/6to4/Teredo)", () => {
  for (const ip of [
    "::ffff:127.0.0.1", // dotted mapped
    "::ffff:7f00:1", // hex mapped = 127.0.0.1 (the form new URL() actually emits)
    "::ffff:a9fe:a9fe", // hex mapped = 169.254.169.254 metadata
    "::ffff:10.5.5.5", // mapped RFC-1918
    "::7f00:1", // IPv4-compatible loopback
    "64:ff9b::a9fe:a9fe", // NAT64 -> 169.254.169.254 metadata
    "64:ff9b::7f00:1", // NAT64 -> 127.0.0.1
    "2002:7f00:1::", // 6to4 wrapping 127.0.0.1
    "2001::80ff:fffe", // Teredo: client v4 = ~(0x80ff,0xfffe) = 127.0.0.1
  ]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test("isBlockedIp allows public addresses (incl. public embedded-v4 forms)", () => {
  for (const ip of [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "::ffff:8.8.8.8", // mapped public
    "2002:0808:0808::", // 6to4 of 8.8.8.8 (public)
  ]) {
    assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
  }
});

test("assertUrlSafe rejects non-http(s) schemes", async () => {
  for (const url of ["file:///etc/passwd", "ftp://example.com", "gopher://example.com"]) {
    await assert.rejects(assertUrlSafe(url), SsrfError, url);
  }
});

test("assertUrlSafe rejects embedded credentials", async () => {
  await assert.rejects(assertUrlSafe("http://user:pass@8.8.8.8/"), SsrfError);
});

test("assertUrlSafe rejects literal internal targets", async () => {
  for (const url of [
    "http://127.0.0.1:4000/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:8080/",
    "http://192.168.0.1/",
    "http://10.1.2.3/",
  ]) {
    await assert.rejects(assertUrlSafe(url), SsrfError, url);
  }
});

test("assertUrlSafe normalizes numeric-encoded loopback (decimal)", async () => {
  // 2130706433 === 127.0.0.1 — getaddrinfo resolves it locally, no network.
  await assert.rejects(assertUrlSafe("http://2130706433/"), SsrfError);
});

test("assertUrlSafe rejects localhost (resolves to loopback)", async () => {
  await assert.rejects(assertUrlSafe("http://localhost:3000/"), SsrfError);
});

test("assertUrlSafe blocks IPv4-mapped IPv6 THROUGH new URL() (the real bypass)", async () => {
  // new URL() serializes these to the hex mapped form (e.g. ::ffff:a9fe:a9fe),
  // which is exactly the string the guard must catch — assert via the URL, not
  // a hand-fed literal, so a dotted-only check can't pass this.
  for (const url of [
    "http://[::ffff:169.254.169.254]/latest/meta-data/", // metadata
    "http://[::ffff:127.0.0.1]/", // loopback
    "http://[::ffff:7f00:1]/", // loopback, already-hex
    "http://[::ffff:10.5.5.5]/", // RFC-1918
    "http://[64:ff9b::a9fe:a9fe]/", // NAT64 -> metadata
  ]) {
    await assert.rejects(assertUrlSafe(url), SsrfError, url);
    assert.equal(await isUrlSafe(url), false, url);
  }
});

test("assertUrlSafe allows a public literal IP (negative control)", async () => {
  // Fast path (literal IP, no DNS) — proves the guard does not block everything.
  await assert.doesNotReject(assertUrlSafe("http://8.8.8.8/"));
  assert.equal(await isUrlSafe("https://1.1.1.1/"), true);
});

test("assertUrlSafe DNS loop: allows a host that resolves public, blocks one that resolves private", async () => {
  try {
    // Positive: hostname resolving to a public address passes the lookup loop.
    __setResolverForTests(async () => [{ address: "93.184.216.34" }]);
    await assert.doesNotReject(assertUrlSafe("https://scrape-target.example/"));

    // Any private answer in the set rejects (DNS-rebinding record shape).
    __setResolverForTests(async () => [{ address: "93.184.216.34" }, { address: "127.0.0.1" }]);
    await assert.rejects(assertUrlSafe("https://scrape-target.example/"), SsrfError);

    // Empty resolution rejects.
    __setResolverForTests(async () => []);
    await assert.rejects(assertUrlSafe("https://scrape-target.example/"), SsrfError);
  } finally {
    __setResolverForTests(null);
  }
});
