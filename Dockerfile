FROM node:lts-alpine3.23

WORKDIR /build

COPY . .
RUN npm install
CMD ["npx", "ts-node", "Main.ts"]