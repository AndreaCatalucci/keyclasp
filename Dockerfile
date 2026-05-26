FROM node:22-alpine

WORKDIR /app

# Install all deps (including devDeps for typescript build)
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and build
COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

# Copy Docker helper scripts
COPY docker-entrypoint.sh docker-init.js ./
RUN chmod +x docker-entrypoint.sh

ENV KEYBLIND_HTTP_PORT=3100
ENV NODE_ENV=production
EXPOSE 3100

ENTRYPOINT ["./docker-entrypoint.sh"]
