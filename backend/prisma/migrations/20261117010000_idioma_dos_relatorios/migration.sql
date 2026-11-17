-- idioma escolhido pelo usuário para os textos dos achados
ALTER TABLE "User" ADD COLUMN "language" TEXT NOT NULL DEFAULT 'pt-BR';

-- cache de traduções dos textos das regras (um registro por idioma + texto)
CREATE TABLE "TranslationCache" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "language" TEXT NOT NULL,
    "sourceHash" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX "TranslationCache_language_sourceHash_key" ON "TranslationCache"("language", "sourceHash");
