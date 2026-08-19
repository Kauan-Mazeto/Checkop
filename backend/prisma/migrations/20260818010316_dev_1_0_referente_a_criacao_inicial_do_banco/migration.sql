-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "role" TEXT NOT NULL DEFAULT 'DEV',
    "googleId" TEXT,
    "resetPasswordToken" TEXT,
    "resetPasswordExpires" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "password_or_google_required" CHECK ("password" IS NOT NULL OR "googleId" IS NOT NULL)
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "targetUrl" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'DEVELOPMENT',
    "safeMode" BOOLEAN NOT NULL DEFAULT true,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "startedAt" DATETIME,
    "finishedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    CONSTRAINT "Scan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL DEFAULT 'MEDIUM',
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "tool" TEXT NOT NULL,
    "affectedUrl" TEXT,
    "parameter" TEXT,
    "cveId" TEXT,
    "cvssScore" REAL,
    "rawRequest" TEXT,
    "rawResponse" TEXT,
    "remediation" TEXT,
    "owaspUrl" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_googleId_key" ON "User"("googleId");
