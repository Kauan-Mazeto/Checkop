-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "role" TEXT NOT NULL DEFAULT 'DEV',
    "googleId" TEXT,
    "resetPasswordToken" TEXT,
    "resetPasswordExpires" DATETIME,
    "resetPasswordRequestedAt" DATETIME,
    "resetPasswordAttempts" INTEGER NOT NULL DEFAULT 0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_User" ("createdAt", "email", "googleId", "id", "name", "password", "resetPasswordExpires", "resetPasswordRequestedAt", "resetPasswordToken", "role", "updatedAt") SELECT "createdAt", "email", "googleId", "id", "name", "password", "resetPasswordExpires", "resetPasswordRequestedAt", "resetPasswordToken", "role", "updatedAt" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "User_googleId_key" ON "User"("googleId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
