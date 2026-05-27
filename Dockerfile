FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

ENV PORT=3000
ENV KEYBLIND_AUTO_INIT=true
EXPOSE 3000

CMD ["node", "dist/cli.js", "start", "--http", "--port", "3000"]
