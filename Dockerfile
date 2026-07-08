# ---- Build Stage ----
FROM node:26-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

# ---- Runtime Stage ----
FROM node:26-alpine

RUN addgroup -g 1001 keyblind && \
    adduser -u 1001 -G keyblind -s /bin/sh -D keyblind

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY dist ./dist
COPY package.json ./

RUN mkdir -p /home/keyblind/.keyblind && \
    chown -R keyblind:keyblind /home/keyblind/.keyblind /app

USER keyblind

EXPOSE 3100

ENV KEYBLIND_AUTO_INIT=true
ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3100/health || exit 1

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["start", "--http", "--port", "3100"]
