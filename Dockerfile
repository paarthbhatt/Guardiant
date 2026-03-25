# ============================================================
# Stage 1: Builder
# ============================================================
FROM node:20-alpine AS builder

# Install pnpm
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

WORKDIR /app

# Copy manifests first for better layer caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY apps/cli/package.json ./apps/cli/
COPY apps/web/package.json ./apps/web/
COPY packages/core/package.json ./packages/core/
COPY packages/shared/package.json ./packages/shared/
COPY packages/database/package.json ./packages/database/
COPY packages/queue/package.json ./packages/queue/

# Install all dependencies (including dev for build)
RUN pnpm install --frozen-lockfile

# Copy source
COPY . .

# Build all packages
RUN pnpm build

# ============================================================
# Stage 2: Production image
# ============================================================
FROM node:20-alpine AS production

LABEL org.opencontainers.image.title="Guardiant"
LABEL org.opencontainers.image.description="Agentic Security Platform for Vibe-Coded Applications"
LABEL org.opencontainers.image.licenses="MIT"

RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

# Create non-root user
RUN addgroup -S guardiant && adduser -S guardiant -G guardiant

WORKDIR /app

# Copy manifests for production install
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/cli/package.json ./apps/cli/
COPY apps/web/package.json ./apps/web/
COPY packages/core/package.json ./packages/core/
COPY packages/shared/package.json ./packages/shared/
COPY packages/database/package.json ./packages/database/
COPY packages/queue/package.json ./packages/queue/

# Install ONLY production dependencies
RUN pnpm install --frozen-lockfile --prod

# Copy built artifacts from builder stage
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/database/dist ./packages/database/dist
COPY --from=builder /app/packages/queue/dist ./packages/queue/dist
COPY --from=builder /app/apps/cli/dist ./apps/cli/dist
COPY --from=builder /app/apps/web ./apps/web

# Set ownership
RUN chown -R guardiant:guardiant /app

# Use non-root user
USER guardiant

# Data directory for SQLite database
VOLUME ["/data"]
ENV DATABASE_PATH=/data/guardiant.db
ENV LOG_LEVEL=info

# Expose web dashboard port
EXPOSE 3000

# Default entrypoint serves the web dashboard using a simple static server.
# Override with: docker run guardiant guardiant scan <url>
CMD ["node", "--experimental-vm-modules", "apps/cli/dist/index.js", "--help"]
