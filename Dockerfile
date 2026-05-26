FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY dist/ dist/

ENV KEYBLIND_HTTP_PORT=3100
EXPOSE 3100

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["start", "--http"]
