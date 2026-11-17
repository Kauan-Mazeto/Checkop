-- CVSS 3.1 calculado por vetor + confiança da ferramenta no achado
ALTER TABLE "Finding" ADD COLUMN "cvssVector" TEXT;
ALTER TABLE "Finding" ADD COLUMN "cvssSource" TEXT;
ALTER TABLE "Finding" ADD COLUMN "confidence" TEXT;
