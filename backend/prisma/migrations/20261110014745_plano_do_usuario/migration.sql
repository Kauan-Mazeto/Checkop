-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "role" TEXT NOT NULL DEFAULT 'DEV',
    "plan" TEXT NOT NULL DEFAULT 'FREE',
    "googleId" TEXT,
    "resetPasswordToken" TEXT,
    "resetPasswordExpires" DATETIME,
    "resetPasswordRequestedAt" DATETIME,
    "resetPasswordAttempts" INTEGER NOT NULL DEFAULT 0,
    "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
    "accountLockedUntil" DATETIME,
    "tokenVersion" INTEGER NOT NULL DEFAULT 0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_User" ("accountLockedUntil", "createdAt", "email", "failedLoginAttempts", "googleId", "id", "name", "password", "resetPasswordAttempts", "resetPasswordExpires", "resetPasswordRequestedAt", "resetPasswordToken", "role", "tokenVersion", "updatedAt") SELECT "accountLockedUntil", "createdAt", "email", "failedLoginAttempts", "googleId", "id", "name", "password", "resetPasswordAttempts", "resetPasswordExpires", "resetPasswordRequestedAt", "resetPasswordToken", "role", "tokenVersion", "updatedAt" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "User_googleId_key" ON "User"("googleId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
