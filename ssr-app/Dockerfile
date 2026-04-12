FROM node:12-alpine@sha256:d4b15b3d48f42059a15bd659be60afe21762aae9d6cbea6f124440895c27db68
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY server.js ./
CMD ["node", "server.js"]
