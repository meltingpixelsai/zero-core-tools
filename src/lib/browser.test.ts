import { test } from "node:test";
import assert from "node:assert/strict";
import { browserLaunchOptions } from "./browser.js";

test("the browser launch leaves SIGINT, SIGTERM and SIGHUP to the server's graceful shutdown", () => {
  // Playwright's defaults close the browser and exit the process on these signals, cutting off paid calls.
  const options = browserLaunchOptions("http://127.0.0.1:1");
  assert.equal(options.handleSIGINT, false);
  assert.equal(options.handleSIGTERM, false);
  assert.equal(options.handleSIGHUP, false);
});
