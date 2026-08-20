import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import timeout from 'connect-timeout';
import authRoutes from './routes/auth_routes.js';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();
const PORT = process.env.PORT;
const requiredEnvVars = ['JWT_SECRET', 'DATABASE_URL', 'CLIENT_URL', 'PORT'];
const missing = requiredEnvVars.filter((key) => !process.env[key]);

// quando for para producao, essa variavel vai ser false, entao ele vai rodar
// para pegar o ip do usuario e nao do serv
if (!process.env.MODO_DEV) {
  app.set('trust proxy', true);
}

if (missing.length > 0) {
  console.error('Variáveis de ambiente ausentes.');
  process.exit(1);
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
    },
  },
  hsts: {
    maxAge: 63072000, // 2 anos
    includeSubDomains: true,
  },
}));

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));

app.use(timeout('25s'));
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use('/api/auth', authRoutes);

// fallback, para se nao achar, retornar aqui, sem estourar banco
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

app.listen(PORT, () => {
  console.log(`Servidor Checkop rodando na porta ${PORT}`);
});

// p/ deploy, desligar automaticamente
process.on('SIGTERM', () => {
  server.close(() => {
    console.log('Servidor encerrado.');
    process.exit(0);
  });
});