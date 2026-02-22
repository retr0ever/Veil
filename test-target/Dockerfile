FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json ./
RUN npm install --production

FROM node:20-alpine

# Non-root user for container hardening
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser

WORKDIR /app

# Copy built dependencies
COPY --from=builder /app/node_modules ./node_modules
COPY package.json server.js ./

# Create writable dirs for SQLite and temp files (owned by appuser)
RUN mkdir -p /tmp/data && chown -R appuser:appuser /tmp /app

USER appuser

EXPOSE 3001

# Node runs as non-root, no shell needed
CMD ["node", "server.js"]
