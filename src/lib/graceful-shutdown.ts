import type { Server } from "node:http";

/**
 * Lets requests in flight finish when the process manager stops or restarts
 * the server. Paid tools settle before they run, so a call cut off mid-tool by
 * a restart is charged and never answered.
 *
 * On SIGINT or SIGTERM the server stops accepting connections, closes idle
 * keep-alive ones, and exits once every request in flight has been answered,
 * or after `graceMs` at the latest. The process manager's kill_timeout
 * (ecosystem.config.cjs) must be longer than `graceMs`, or it kills the
 * process first.
 */

/** Covers a scrape (30 s page timeout) plus an LLM call; a restart waits at most this long. */
export const SHUTDOWN_GRACE_MS = 90_000;

export interface GracefulShutdownOptions {
  graceMs?: number;
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
  const log = options.log ?? ((message: string) => console.log(message));
  const exit = options.exit ?? ((code: number) => process.exit(code));
  let closing = false;
  let exited = false;

  const shutdown = (reason: string): void => {
    if (closing) return;
    closing = true;
    log(`[shutdown] ${reason}: not accepting new connections; waiting up to ${graceMs / 1000} s for requests in flight`);

    // A connection whose request is answered while we wait is idle from then on: close it too.
    const sweep = setInterval(() => server.closeIdleConnections(), 250);
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const finish = (message: string): void => {
      if (exited) return;
      exited = true;
      clearInterval(sweep);
      clearTimeout(deadline);
      log(message);
      exit(0);
    };
    deadline = setTimeout(() => finish("[shutdown] grace period over; exiting with requests still in flight"), graceMs);
    server.close(() => finish("[shutdown] no requests in flight; exiting"));
    server.closeIdleConnections();
  };

  for (const signal of options.signals ?? ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => shutdown(signal));
  }
  return shutdown;
}
