FROM node:25-alpine
# Pull in OS security fixes and a current npm (the npm bundled with the base image carries older dependencies).
RUN apk upgrade --no-cache && npm install -g npm@11
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Vite writes its cache under node_modules, so the unprivileged user must own /app.
RUN chown -R node:node /app
USER node
EXPOSE 5173
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:5173/ || exit 1
CMD ["npm", "run", "dev"]
