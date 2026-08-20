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

const RESET_CODE_TTL_MINUTES = 10;
const RESET_REQUEST_COOLDOWN_HOURS = 24;
const MAX_RESET_ATTEMPTS = 3;

const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    // tudo validade pelo Zod

    const hashedPassword = await hashPassword(password);

    const newUser = await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          name,
          email,
          password: hashedPassword,
          role,
        },
      });

      await tx.termsAcceptance.create({
        data: {
          userId: user.id,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'] || null,
        },
      });

      return user;
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

// rf-04
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    // limite de 1 solicitacao a cada 24h por usuario. se estiver dentro do
    // cooldown, ignora silenciosamente - a resposta continua a mesma, pra nao
    // revelar que a conta existe nem que ja tinha um pedido em andamento.
    const dentroDoCooldown = user?.resetPasswordRequestedAt && Date.now() - user.resetPasswordRequestedAt.getTime() < RESET_REQUEST_COOLDOWN_HOURS * 60 * 60 * 1000;

    // só gera e envia código se existir uma conta local com senha
    // (contas google-only não têm senha pra redefinir).
    // a resposta ao cliente é sempre a mesma, pra não revelar se o e-mail existe.
    if (user && user.password && !dentroDoCooldown) {
      const code = generateResetCode();
      const codeHash = hashResetCode(code);
      const expiresAt = new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60 * 1000);

      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetPasswordToken: codeHash,
          resetPasswordExpires: expiresAt,
          resetPasswordRequestedAt: new Date(),
        },
      });

      try {
        await sendPasswordResetEmail(user.email, user.name, code);
      } catch (mailErr) {
        // não revela falha de envio ao cliente, só loga internamente.
        console.error('Erro ao enviar e-mail de redefinição de senha:', mailErr);
      }
    }

    return res.status(200).json({
      message: 'Se o e-mail informado estiver cadastrado, um código de verificação foi enviado.',
    });
  } catch (error) {
    console.error('Erro em forgotPassword:', error);
    return res.status(500).json({ error: 'Erro interno ao solicitar redefinição de senha.' });
  }
};

// rf-04
const resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    const codeInvalido = () =>
      res.status(400).json({ error: 'Código inválido ou expirado.' });

    if (!user || !user.resetPasswordToken || !user.resetPasswordExpires) {
      return codeInvalido();
    }

    const expirado = user.resetPasswordExpires.getTime() < Date.now();
    if (expirado) {
      return codeInvalido();
    }

    // se ja bateu no limite de tentativas (por alguma corrida entre requests,
    // por exemplo), trata como invalido sem nem comparar o codigo de novo.
    if (user.resetPasswordAttempts >= MAX_RESET_ATTEMPTS) {
      return codeInvalido();
    }

    const codigoValido = compareResetCode(code, user.resetPasswordToken);

    if (!codigoValido) {
      const tentativasRestantes = MAX_RESET_ATTEMPTS - (user.resetPasswordAttempts + 1);

      if (tentativasRestantes <= 0) {
        // estourou o limite de tentativas: invalida o codigo e cancela a
        // solicitacao. o resetPasswordRequestedAt continua intacto de
        // proposito, entao o cooldown de 24h segue valendo e a pessoa nao
        // consegue pedir um codigo novo na hora - limita o brute force a no
        // maximo 3 tentativas por dia por conta.
        await prisma.user.update({
          where: { id: user.id },
          data: {
            resetPasswordToken: null,
            resetPasswordExpires: null,
            resetPasswordAttempts: 0,
          },
        });
      } else {
        await prisma.user.update({
          where: { id: user.id },
          data: { resetPasswordAttempts: { increment: 1 } },
        });
      }

      return codeInvalido();
    }

    const hashedPassword = await hashPassword(newPassword);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
        resetPasswordRequestedAt: null,
        resetPasswordAttempts: 0,
      },
    });

    return res.status(200).json({
      message: 'Senha redefinida com sucesso. Faça login com a nova senha.',
    });
  } catch (error) {
    console.error('Erro em resetPassword:', error);
    return res.status(500).json({ error: 'Erro interno ao redefinir senha.' });
  }
};

export default { register, login, googleLogin, forgotPassword, resetPassword };