FROM node:22-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc

FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
RUN npx playwright install --with-deps chromium
COPY --from=builder /app/dist ./dist

# This image runs as root in a container, where Chromium cannot start its sandbox; the launch stays unsandboxed
# here, as it was before src/lib/browser.ts turned the sandbox on (the server warns once at the first launch).
# The production host runs the server from ecosystem.config.cjs, not this image, with the sandbox on.
ENV BROWSER_SANDBOX=off

EXPOSE 8403
CMD ["node", "dist/index.js"]
