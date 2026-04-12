FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY exploit.js safe.js test.js ./
CMD ["node", "exploit.js"]
