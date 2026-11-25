-- PoC completa: payload do ataque e comando para reproduzir
ALTER TABLE "Finding" ADD COLUMN "attack" TEXT;
ALTER TABLE "Finding" ADD COLUMN "reproduction" TEXT;
