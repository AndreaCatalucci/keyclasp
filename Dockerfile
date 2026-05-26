FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY dist/ dist/
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

ENV KEYBLIND_HTTP_PORT=3100
EXPOSE 3100

ENTRYPOINT ["./docker-entrypoint.sh"]
