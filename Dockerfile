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

ENV PORT=3000
ENV NODE_ENV=production
EXPOSE 3000

ENTRYPOINT ["./docker-entrypoint.sh"]
