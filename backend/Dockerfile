# API Node (Express + Prisma/SQLite). O banco fica no volume /data.
FROM node:22-bookworm-slim

# better-sqlite3 é nativo: ferramentas de build caso o binário pronto não sirva
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY prisma ./prisma
COPY prisma.config.ts ./
COPY src ./src

# o prisma.config.ts exige DATABASE_URL já no build (para o generate)
ENV DATABASE_URL="file:/data/database.db"
RUN npx prisma generate \
 && mkdir -p /data && chown -R node:node /data /app

USER node
EXPOSE 8080
# aplica as migrações pendentes a cada subida (cria o banco na primeira vez)
CMD ["sh", "-c", "npx prisma migrate deploy && node src/server.js"]
