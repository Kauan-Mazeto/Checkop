-- RF-22: preferência de notificação por e-mail ao terminar uma varredura
ALTER TABLE "User" ADD COLUMN "notifyScanEmail" BOOLEAN NOT NULL DEFAULT true;
