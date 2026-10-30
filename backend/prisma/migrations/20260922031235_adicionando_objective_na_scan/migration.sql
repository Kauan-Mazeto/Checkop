-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Scan" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "targetUrl" TEXT NOT NULL,
    "objective" TEXT NOT NULL DEFAULT 'FULL_SCAN',
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
INSERT INTO "new_Scan" ("authorizationConfirmedAt", "authorizationIp", "createdAt", "environment", "finishedAt", "id", "resolvedIps", "safeMode", "startedAt", "status", "suspiciousEnvironment", "targetUrl", "userId") SELECT "authorizationConfirmedAt", "authorizationIp", "createdAt", "environment", "finishedAt", "id", "resolvedIps", "safeMode", "startedAt", "status", "suspiciousEnvironment", "targetUrl", "userId" FROM "Scan";
DROP TABLE "Scan";
ALTER TABLE "new_Scan" RENAME TO "Scan";
CREATE INDEX "Scan_suspiciousEnvironment_idx" ON "Scan"("suspiciousEnvironment");
CREATE INDEX "Scan_userId_idx" ON "Scan"("userId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
