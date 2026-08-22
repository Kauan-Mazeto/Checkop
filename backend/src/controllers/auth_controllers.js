import { hashPassword, comparePassword, generateToken, buildCookieOptions, generateResetCode, hashResetCode, compareResetCode } from '../constants/utils.js';
import { verifyGoogleToken } from '../lib/google_client.js';
import { sendPasswordResetEmail } from '../lib/mailer.js';
import { logLoginAttempt } from '../lib/audit_log.js';
import prisma from '../lib/prisma.js';
import bcrypt from 'bcryptjs';

const DUMMY_PASSWORD_HASH = bcrypt.hashSync(
  `checkop-dummy-${Date.now()}-${Math.random()}`,
  11
);

const RESET_CODE_TTL_MINUTES = 10;
const RESET_REQUEST_COOLDOWN_HOURS = 24;
const MAX_RESET_ATTEMPTS = 3;
const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const ACCOUNT_LOCK_MINUTES = 15;
const DELETE_ACCOUNT_CONFIRMATION_PHRASE = 'EXCLUIR MINHA CONTA';

const clearAuthCookie = (res) => {
  res.clearCookie('token', {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.MODO_DEV !== 'DEV',
    path: '/',
  });
};

const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

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

    res.cookie('token', token, buildCookieOptions());

    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso!',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'Não foi possível concluir o cadastro. Verifique os dados informados.' });
    }
    console.error('Erro no registro:', error);
    return res.status(500).json({ error: 'Erro interno ao cadastrar usuário.' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip;
    const userAgent = req.headers['user-agent'] || null;
    const user = await prisma.user.findUnique({ where: { email } });
    const isCurrentlyLocked = user?.accountLockedUntil && user.accountLockedUntil.getTime() > Date.now();
    const hashToCompare = user?.password ?? DUMMY_PASSWORD_HASH;
    const isPasswordValid = await comparePassword(password, hashToCompare);

    const credenciaisInvalidas = () =>
      res.status(401).json({ error: 'Credenciais inválidas.' });

    if (!user || !user.password || isCurrentlyLocked || !isPasswordValid) {
      // só incrementa o contador de tentativas se a conta existe, tem senha
      // (não é google-only) e ainda não está bloqueada - evita re-bloquear
      // indefinidamente uma conta já travada a cada nova tentativa
      if (user && user.password && !isCurrentlyLocked && !isPasswordValid) {
        const attempts = user.failedLoginAttempts + 1;
        const shouldLock = attempts >= MAX_FAILED_LOGIN_ATTEMPTS;

        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: shouldLock ? 0 : attempts,
            accountLockedUntil: shouldLock
              ? new Date(Date.now() + ACCOUNT_LOCK_MINUTES * 60 * 1000)
              : null,
          },
        });
      }

      await logLoginAttempt({ email, success: false, ip, userAgent, userId: user?.id ?? null });

      return credenciaisInvalidas();
    }

    // login bem-sucedido - reseta qualquer contador/bloqueio pendente
    if (user.failedLoginAttempts > 0 || user.accountLockedUntil) {
      await prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: 0, accountLockedUntil: null },
      });
    }

    await logLoginAttempt({ email, success: true, ip, userAgent, userId: user.id });

    const token = await generateToken(user);

    res.cookie('token', token, buildCookieOptions());

    return res.status(200).json({
      message: 'Login realizado com sucesso!',
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
          data: { name, email, googleId },
        });
      }
    }

    await logLoginAttempt({
      email: user.email,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || null,
      userId: user.id,
    });

    const token = await generateToken(user);

    res.cookie('token', token, buildCookieOptions());

    return res.status(200).json({
      message: 'Login com Google realizado com sucesso!',
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

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    const dentroDoCooldown =
      user?.resetPasswordRequestedAt &&
      Date.now() - user.resetPasswordRequestedAt.getTime() 
        RESET_REQUEST_COOLDOWN_HOURS * 60 * 60 * 1000;

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

    if (user.resetPasswordAttempts >= MAX_RESET_ATTEMPTS) {
      return codeInvalido();
    }

    const codigoValido = compareResetCode(code, user.resetPasswordToken);

    if (!codigoValido) {
      const tentativasRestantes = MAX_RESET_ATTEMPTS - (user.resetPasswordAttempts + 1);

      if (tentativasRestantes <= 0) {
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
        failedLoginAttempts: 0,
        accountLockedUntil: null,
        tokenVersion: { increment: 1 },
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

const logout = async (req, res) => {
  try {
    if (req.userId) {
      await prisma.user.update({
        where: { id: req.userId },
        data: { tokenVersion: { increment: 1 } },
      });
    }
  } catch (error) {
    console.error('Erro ao revogar tokens no logout:', error);
  } finally {
    clearAuthCookie(res);
    return res.status(200).json({ message: 'Logout realizado com sucesso.' });
  }
};

const deleteAccount = async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    if (user.password) {
      const { password } = req.body;
      const isPasswordValid = await comparePassword(password ?? '', user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Senha incorreta.' });
      }
    } else {
      const { confirmation } = req.body;

      if (confirmation !== DELETE_ACCOUNT_CONFIRMATION_PHRASE) {
        return res.status(400).json({
          error: `Para confirmar, envie o campo "confirmation" com o texto exato: "${DELETE_ACCOUNT_CONFIRMATION_PHRASE}"`,
        });
      }
    }

    await prisma.user.delete({ where: { id: user.id } });

    clearAuthCookie(res);

    return res.status(200).json({
      message: 'Conta excluída com sucesso. Todos os seus dados pessoais foram removidos.',
    });
  } catch (error) {
    console.error('Erro ao excluir conta:', error);
    return res.status(500).json({ error: 'Erro interno ao excluir conta.' });
  }
};

// bônus: sem isso, o log de auditoria existe mas ninguém nunca o vê -
// permite ao próprio usuário revisar as últimas tentativas de login na conta
const getLoginHistory = async (req, res) => {
  try {
    const attempts = await prisma.loginAttempt.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: {
        success: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
      },
    });

    return res.status(200).json({ attempts });
  } catch (error) {
    console.error('Erro ao buscar histórico de login:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar histórico de login.' });
  }
};

export default {register , login , googleLogin , forgotPassword , resetPassword , logout , deleteAccount , getLoginHistory};