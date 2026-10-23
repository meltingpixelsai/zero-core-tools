import type { Server } from "node:http";

/**
 * Lets requests in flight finish when the process manager stops or restarts
 * the server. Paid tools settle before they run, so a call cut off mid-tool by
 * a restart is charged and never answered.
 *
 * On SIGINT or SIGTERM the server stops accepting connections, closes idle
 * keep-alive ones, and exits once every request in flight has been answered,
 * or after `graceMs` at the latest. Before exiting it runs `beforeExit` (for
 * example closing a browser) for at most `beforeExitTimeoutMs`. It exits 0 when
 * every request was answered and 1 when the deadline cut some off. A second
 * signal is ignored; the deadline still applies.
 *
 * The process manager's kill_timeout (ecosystem.config.cjs) must be longer than
 * `graceMs` plus `beforeExitTimeoutMs`, or it kills the process first. Anything
 * else in the process that exits on SIGINT (Playwright's default handlers, for
 * one) must be switched off, or it ends the process before the drain.
 */

/** Covers a scrape (30 s page timeout) plus an LLM call; a restart waits at most this long. */
export const SHUTDOWN_GRACE_MS = 90_000;
/** The longest wait for `beforeExit`. */
export const BEFORE_EXIT_TIMEOUT_MS = 3_000;

export interface GracefulShutdownOptions {
  graceMs?: number;
  beforeExit?: () => Promise<unknown>;
  beforeExitTimeoutMs?: number;
  signals?: readonly NodeJS.Signals[];
  log?: (message: string) => void;
  exit?: (code: number) => void;
}

/** Installs the signal handlers and returns the shutdown function (for tests). */
export function installGracefulShutdown(
  server: Pick<Server, "close" | "closeIdleConnections">,
  options: GracefulShutdownOptions = {}
): (reason: string) => void {
  const graceMs = options.graceMs ?? SHUTDOWN_GRACE_MS;
  const beforeExitTimeoutMs = options.beforeExitTimeoutMs ?? BEFORE_EXIT_TIMEOUT_MS;
  const log = options.log ?? ((message: string) => console.log(message));
  const exit = options.exit ?? ((code: number) => process.exit(code));
  let closing = false;
  let finished = false;

  const shutdown = (reason: string): void => {
    if (closing) return;
    closing = true;
    log(`[shutdown] ${reason}: not accepting new connections; waiting up to ${graceMs / 1000} s for requests in flight`);

    // A connection whose request is answered while we wait is idle from then on: close it too.
    const sweep = setInterval(() => server.closeIdleConnections(), 250);
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const finish = (message: string, code: number): void => {
      if (finished) return;
      finished = true;
      clearInterval(sweep);
      clearTimeout(deadline);
      log(message);
      const beforeExit = options.beforeExit;
      if (!beforeExit) return exit(code);
      let exited = false;
      let cap: ReturnType<typeof setTimeout> | undefined;
      const done = (): void => {
        if (exited) return;
        exited = true;
        clearTimeout(cap);
        exit(code);
      };
      cap = setTimeout(() => {
        log("[shutdown] cleanup took too long; exiting anyway");
        done();
      }, beforeExitTimeoutMs);
      Promise.resolve()
        .then(beforeExit)
        .catch((err: unknown) => log(`[shutdown] cleanup failed: ${err instanceof Error ? err.message : String(err)}`))
        .finally(done);
    };
    deadline = setTimeout(() => finish("[shutdown] grace period over; exiting with requests still in flight", 1), graceMs);
    server.close(() => finish("[shutdown] no requests in flight; exiting", 0));
    server.closeIdleConnections();
  };

  for (const signal of options.signals ?? ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => shutdown(signal));
  }
  return shutdown;
}
