import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

export const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(11);
  return await bcrypt.hash(password, salt);
};

export const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

export const generateResetCode = () => {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
};

export const hashResetCode = (code) => {
  return crypto.createHmac('sha256', process.env.RESET_CODE_SECRET).update(code).digest('hex');
};

export const compareResetCode = (code, hash) => {
  return hashResetCode(code) === hash;
};

export const generateToken = async (user) => {
  return new Promise((resolve, reject) => {
    jwt.sign(
      { id: user.id, role: user.role, email: user.email, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: process.env.EXPIRES_IN },
      (err, token) => {
        if (err) {
          reject(err);
        } else {
          resolve(token);
        }
      }
    );
  });
};

export const verifyToken = async (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};

export const buildCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.MODO_DEV !== 'DEV',
  sameSite: 'strict',
  maxAge: 24 * 60 * 60 * 1000,
  path: '/',
});