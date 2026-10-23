module.exports = {
  apps: [
    {
      name: "harvey-tools",
      script: "dist/index.js",
      cwd: "/home/deploy/projects/harvey-tools",
      node_args: "--enable-source-maps",
      env: {
        NODE_ENV: "production",
        PORT: 8403,
      },
      max_memory_restart: "512M",
      // Longer than the 90 s shutdown grace (src/lib/graceful-shutdown.ts), so a stop
      // or restart lets paid calls in flight finish instead of killing them at 1.6 s.
      kill_timeout: 95000,
      autorestart: true,
      watch: false,
    },
  ],
};
