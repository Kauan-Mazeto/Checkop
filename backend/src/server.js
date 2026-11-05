import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import timeout from 'connect-timeout';
import dotenv from 'dotenv';
import authRoutes from './routes/auth_routes.js';
import { globalLimiter } from './middlewares/rate_limit_middleware.js';
import sanitizeMiddleware from './middlewares/sanitize_middleware.js';
import scanRoutes from './routes/scan_routes.js';
import privacyRoutes from './routes/privacy_routes.js';
import sastRoutes from './routes/sast_routes.js';
import prisma from './lib/prisma.js';
dotenv.config();

const app = express();
const PORT = process.env.PORT;

const requiredEnvVars = ['JWT_SECRET', 'DATABASE_URL', 'CLIENT_URL', 'PORT'];
const missing = requiredEnvVars.filter((key) => !process.env[key]);

if (missing.length > 0) {
  console.error("Variáveis de ambiente ausentes.");
  process.exit(1);
}

// quando for para producao, essa variavel vai ser false, entao ele vai rodar
// para pegar o ip do usuario e nao do serv
if (!process.env.MODO_DEV) {
  app.set('trust proxy', true);
}

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
app.use('/api/scans', scanRoutes);
app.use('/api/sast', sastRoutes);
app.use('/api/privacy', privacyRoutes);

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
});

// p/ deploy, desligar automaticamente
process.on('SIGTERM', () => {
  server.close(() => {
    console.log('Servidor encerrado.');
    process.exit(0);
  });
});