import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
dotenv.config();

import authRoutes from './routes/auth_routes.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));

app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'API Checkop rodando.' });
});

app.use('/api/auth', authRoutes);

// fallback, para se nao achar, retornar aqui, sem estourar banco
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

app.use((err, req, res, next) => {
  console.error('[ERRO INTERNO]:', err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Erro interno no servidor.',
  });
});

app.listen(PORT, () => {
  console.log(`Servidor Checkop rodando na porta ${PORT}`);
});