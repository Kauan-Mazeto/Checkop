-- histórico de aceites: cada nova versão dos Termos aceita vira um registro
-- (antes era um só por usuário e a versão nova não tinha onde ser gravada)
DROP INDEX "TermsAcceptance_userId_key";
CREATE INDEX "TermsAcceptance_userId_acceptedAt_idx" ON "TermsAcceptance"("userId", "acceptedAt");
