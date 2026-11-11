-- CreateTable
CREATE TABLE "Target" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "verificationMethod" TEXT NOT NULL,
    "verificationToken" TEXT NOT NULL,
    "verifiedAt" DATETIME,
    "lastCheckedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Target_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT,
    "action" TEXT NOT NULL,
    "resourceType" TEXT,
    "resourceId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "details" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

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
    "activeScanConfirmedAt" DATETIME,
    "activeScanConfirmationIp" TEXT,
    "targetId" TEXT,
    "startedAt" DATETIME,
    "finishedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    CONSTRAINT "Scan_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Scan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Scan" ("authorizationConfirmedAt", "authorizationIp", "createdAt", "environment", "finishedAt", "id", "objective", "resolvedIps", "safeMode", "startedAt", "status", "suspiciousEnvironment", "targetUrl", "userId") SELECT "authorizationConfirmedAt", "authorizationIp", "createdAt", "environment", "finishedAt", "id", "objective", "resolvedIps", "safeMode", "startedAt", "status", "suspiciousEnvironment", "targetUrl", "userId" FROM "Scan";
DROP TABLE "Scan";
ALTER TABLE "new_Scan" RENAME TO "Scan";
CREATE INDEX "Scan_suspiciousEnvironment_idx" ON "Scan"("suspiciousEnvironment");
CREATE INDEX "Scan_targetId_idx" ON "Scan"("targetId");
CREATE INDEX "Scan_userId_idx" ON "Scan"("userId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE INDEX "Target_userId_idx" ON "Target"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "Target_userId_hostname_scope_key" ON "Target"("userId", "hostname", "scope");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");
