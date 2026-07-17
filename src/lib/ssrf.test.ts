import { test } from "node:test";
import assert from "node:assert/strict";
import { assertUrlSafe, isBlockedIp, isUrlSafe, SsrfError } from "./ssrf.js";

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

test("isBlockedIp flags loopback/ULA/link-local/mapped v6", () => {
  for (const ip of ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "::ffff:127.0.0.1"]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test("isBlockedIp allows public addresses", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]) {
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

test("assertUrlSafe allows a public literal IP (negative control)", async () => {
  // Fast path (literal IP, no DNS) — proves the guard does not block everything.
  await assert.doesNotReject(assertUrlSafe("http://8.8.8.8/"));
  assert.equal(await isUrlSafe("https://1.1.1.1/"), true);
});
