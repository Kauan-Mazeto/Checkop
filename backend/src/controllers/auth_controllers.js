import { hashPassword, comparePassword, generateToken } from '../constants/utils.js';
import { verifyGoogleToken } from '../lib/google_client.js';
import prisma from '../lib/prisma.js';
import bcrypt from 'bcryptjs';

// Hash "morto" gerado uma única vez no boot — usado só pra manter o tempo de
// resposta constante quando o usuário não existe ou é conta Google-only.
// Nunca corresponde a nenhuma senha real.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(
  `checkop-dummy-${Date.now()}-${Math.random()}`,
  11
);

const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    // já foi validado pelo Zod

    const hashedPassword = await hashPassword(password);

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role,
      },
    });

    const token = await generateToken(newUser);

    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso!',
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'E-mail já cadastrado.' });
    }
    console.error('Erro no registro:', error);
    return res.status(500).json({ error: 'Erro interno ao cadastrar usuário.' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    // SEMPRE roda o bcrypt.compare, mesmo se o usuário não existir ou for conta
    // Google-only (sem password). Isso evita dois vazamentos:
    // 1) mensagem diferente revelando que a conta existe / é Google-only
    // 2) tempo de resposta diferente revelando a mesma informação
    const hashToCompare = user?.password ?? DUMMY_PASSWORD_HASH;
    const isPasswordValid = await comparePassword(password, hashToCompare);

    if (!user || !user.password || !isPasswordValid) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const token = await generateToken(user);

    return res.status(200).json({
      message: 'Login realizado com sucesso!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Erro no login:', error);
    return res.status(500).json({ error: 'Erro interno ao realizar login.' });
  }
};

// RF-03 
const googleLogin = async (req, res) => {
  try {
    const { credential } = req.body;

    let payload;
    try {
      payload = await verifyGoogleToken(credential);
    } catch (err) {
      return res.status(401).json({ error: 'Token do Google inválido ou expirado.' });
    }

    if (!payload.email_verified) {
      return res.status(401).json({ error: 'E-mail do Google não verificado.' });
    }

    const { sub: googleId, email, name } = payload;

    let user = await prisma.user.findUnique({ where: { googleId } });

    if (!user) {
      // Se já existe uma conta local com o mesmo e-mail, vincula em vez de duplicar.
      // Confiável porque o Google já garantiu, via email_verified, que o e-mail é real.
      user = await prisma.user.findUnique({ where: { email } });

      if (user) {
        if (!user.googleId) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { googleId },
          });
        }
      } else {
        user = await prisma.user.create({
          data: {
            name,
            email,
            googleId
          },
        });
      }
    }

    const token = await generateToken(user);

    return res.status(200).json({
      message: 'Login com Google realizado com sucesso!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Erro no login com Google:', error);
    return res.status(500).json({ error: 'Erro interno ao realizar login com Google.' });
  }
};

export default { register, login, googleLogin };