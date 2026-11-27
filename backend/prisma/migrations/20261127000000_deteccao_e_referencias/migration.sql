-- Como a ferramenta concluiu que é falha e os links de referência dela
ALTER TABLE "Finding" ADD COLUMN "detection" TEXT;
ALTER TABLE "Finding" ADD COLUMN "references" TEXT;
