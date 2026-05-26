FROM node:22-alpine

RUN apk add --no-cache python3 make g++

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
