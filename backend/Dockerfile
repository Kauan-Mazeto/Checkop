# API Node (Express + Prisma/SQLite). O banco fica no volume /data.
FROM node:22-bookworm-slim

# better-sqlite3 é nativo: ferramentas de build caso o binário pronto não sirva
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# pastas do app e do banco já com o dono certo. Nada de "chown -R" depois:
# varrer o node_modules no Docker do Windows levava ~30 min a cada build.
RUN mkdir -p /app /data && chown node:node /app /data
WORKDIR /app
USER node

# dependências primeiro: esta camada só é refeita quando o package-lock muda
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node prisma ./prisma
COPY --chown=node:node prisma.config.ts ./
# o prisma.config.ts exige DATABASE_URL já no build (para o generate)
ENV DATABASE_URL="file:/data/database.db"
RUN npx prisma generate

# o código vem por último: mudar só o código não refaz as camadas de cima
COPY --chown=node:node src ./src

EXPOSE 8080
# aplica as migrações pendentes a cada subida (cria o banco na primeira vez)
CMD ["sh", "-c", "npx prisma migrate deploy && node src/server.js"]
