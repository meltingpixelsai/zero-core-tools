module.exports = {
  apps: [
    {
      name: "harvey-tools",
      script: "dist/index.js",
      cwd: "/home/deploy/projects/harvey-tools",
      // V8 heap cap well under max_memory_restart (512M): under a burst of requests V8 otherwise lets the
      // heap grow past the limit before it collects, and the process manager restarts the server (and drains).
      node_args: "--enable-source-maps --max-old-space-size=320",
      env: {
        NODE_ENV: "production",
        PORT: 8403,
      },
      max_memory_restart: "512M",
      // Longer than the 90 s shutdown grace plus the 3 s browser close
      // (src/lib/graceful-shutdown.ts), so a stop or restart lets paid calls in
      // flight finish instead of killing them at 1.6 s.
      kill_timeout: 100000,
      // Signal only the server, not its Chromium children: the server drains its
      // calls in flight, then closes the browser itself.
      treekill: false,
      autorestart: true,
      watch: false,
    },
  ],
};
