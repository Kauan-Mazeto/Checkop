// precisa ser o 1º import: em ESM os imports rodam antes do corpo do módulo, e
// vários módulos leem process.env no carregamento (ex.: SECURITY_ENGINE_URL)
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import timeout from 'connect-timeout';
import authRoutes from './routes/auth_routes.js';
import { globalLimiter } from './middlewares/rate_limit_middleware.js';
import sanitizeMiddleware from './middlewares/sanitize_middleware.js';
import scanRoutes from './routes/scan_routes.js';
import privacyRoutes from './routes/privacy_routes.js';
import sastRoutes from './routes/sast_routes.js';
import targetRoutes from './routes/target_routes.js';
import adminRoutes from './routes/admin_routes.js';
import { scheduleTemplateUpdates } from './lib/template_updates.js';
import prisma from './lib/prisma.js';
import { scheduleRetentionPurge } from './lib/retention.js';

const app = express();
const PORT = process.env.PORT;

const requiredEnvVars = ['JWT_SECRET', 'EXPIRES_IN', 'RESET_CODE_SECRET', 'ENGINE_TOKEN', 'DATABASE_URL', 'CLIENT_URL', 'PORT'];
const missing = requiredEnvVars.filter((key) => !process.env[key]);

if (missing.length > 0) {
  console.error(`Variáveis de ambiente ausentes: ${missing.join(', ')}`);
  process.exit(1);
}

// IP real do usuário atrás de proxy (ng serve em dev, nginx em produção).
// Só confia no X-Forwarded-For quando quem repassa é um proxy NESTA máquina
// ('loopback'): confiar em qualquer origem ('true') deixava o próprio usuário
// inventar o IP e burlar o limite de tentativas de login e a auditoria.
// Proxy em outra máquina: defina TRUST_PROXY (ex.: "10.0.0.5" ou "1" saltos).
const trustProxy = process.env.TRUST_PROXY?.trim() || 'loopback';
app.set('trust proxy', /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
    },
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
  },
}));

app.use(compression());

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
}));

const timeoutPadrao = timeout('25s');
const timeoutSast = timeout('3m'); // o Semgrep pode levar até 120s
app.use((req, res, next) => (req.path.startsWith('/api/sast') ? timeoutSast : timeoutPadrao)(req, res, next));
app.use(morgan('dev'));
// 10kb para a API toda; só o /api/sast recebe arquivos de código (até 10mb)
const jsonPequeno = express.json({ limit: '10kb' });
const jsonGrande = express.json({ limit: '10mb' });
app.use((req, res, next) => (req.path.startsWith('/api/sast') ? jsonGrande : jsonPequeno)(req, res, next));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use((req, res, next) => (req.path.startsWith('/api/sast') ? next() : sanitizeMiddleware(req, res, next)));
app.use(globalLimiter);

app.use('/api/auth', authRoutes);
app.use('/api/targets', targetRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/sast', sastRoutes);
app.use('/api/privacy', privacyRoutes);
app.use('/api/admin', adminRoutes);

// fallback, para se nao achar, retornar aqui, sem estourar banco
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

const server = app.listen(PORT, async () => {
  console.log(`Servidor Checkop rodando na porta ${PORT}`);

  // varreduras rodam em segundo plano dentro deste processo: se o servidor caiu
  // ou reiniciou no meio de uma, ela ficou presa em RUNNING. Aqui marcamos como
  // FAILED para o usuário poder executar de novo.
  try {
    const { count } = await prisma.scan.updateMany({
      where: { status: 'RUNNING' },
      data: { status: 'FAILED', finishedAt: new Date() },
    });
  } catch (err) {
    console.error('Falha ao limpar varreduras interrompidas:', err);
  }

  scheduleRetentionPurge();
  scheduleTemplateUpdates(); // RF-45
});

// p/ deploy, desligar automaticamente
process.on('SIGTERM', () => {
  server.close(() => {
    console.log('Servidor encerrado.');
    process.exit(0);
  });
});