FROM node:22-alpine

# Build tools for better-sqlite3 native compilation
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

COPY docker-entrypoint.sh docker-init.js ./
RUN chmod +x docker-entrypoint.sh

ENV KEYBLIND_HTTP_PORT=3100
ENV NODE_ENV=production
EXPOSE 3100

ENTRYPOINT ["./docker-entrypoint.sh"]
