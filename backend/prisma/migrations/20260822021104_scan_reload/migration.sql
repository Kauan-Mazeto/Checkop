/*
  Warnings:

  - Added the required column `authorizationConfirmedAt` to the `Scan` table without a default value. This is not possible if the table is not empty.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Scan" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "targetUrl" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'DEVELOPMENT',
    "safeMode" BOOLEAN NOT NULL DEFAULT true,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "resolvedIps" TEXT,
    "suspiciousEnvironment" BOOLEAN NOT NULL DEFAULT false,
    "authorizationConfirmedAt" DATETIME NOT NULL,
    "authorizationIp" TEXT,
    "startedAt" DATETIME,
    "finishedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    CONSTRAINT "Scan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Scan" ("createdAt", "environment", "finishedAt", "id", "safeMode", "startedAt", "status", "targetUrl", "userId") SELECT "createdAt", "environment", "finishedAt", "id", "safeMode", "startedAt", "status", "targetUrl", "userId" FROM "Scan";
DROP TABLE "Scan";
ALTER TABLE "new_Scan" RENAME TO "Scan";
CREATE INDEX "Scan_suspiciousEnvironment_idx" ON "Scan"("suspiciousEnvironment");
CREATE INDEX "Scan_userId_idx" ON "Scan"("userId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
