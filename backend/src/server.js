import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import mongoSanitize from 'express-mongo-sanitize';
import cookieParser from 'cookie-parser';
import timeout from 'connect-timeout';
import dotenv from 'dotenv';
import authRoutes from './routes/auth_routes.js';
import { globalLimiter } from './middlewares/rate_limit_middleware.js';
import scanRoutes from './routes/scan_routes.js';
import privacyRoutes from './routes/privacy_routes.js';
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

app.use(timeout('25s'));
app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(globalLimiter);

app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/privacy', privacyRoutes);

// fallback, para se nao achar, retornar aqui, sem estourar banco
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

const server = app.listen(PORT, () => {
  console.log(`Servidor Checkop rodando na porta ${PORT}`);
});

// p/ deploy, desligar automaticamente
process.on('SIGTERM', () => {
  console.log('SIGTERM recebido, encerrando servidor...');
  server.close(() => {
    console.log('Servidor encerrado.');
    process.exit(0);
  });
});