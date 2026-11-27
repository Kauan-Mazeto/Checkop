-- Histórico da análise de código: só o resumo do resultado, nunca o código enviado
CREATE TABLE "CodeAnalysis" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "depth" TEXT NOT NULL,
    "files" TEXT NOT NULL,
    "findingsCount" INTEGER NOT NULL,
    "severityCounts" TEXT NOT NULL,
    "categoryCounts" TEXT NOT NULL,
    "findings" TEXT NOT NULL,
    "durationSeconds" REAL NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "CodeAnalysis_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "CodeAnalysis_userId_createdAt_idx" ON "CodeAnalysis"("userId", "createdAt");
