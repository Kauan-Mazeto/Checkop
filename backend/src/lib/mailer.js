import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// envia o código de redefinição de senha por e-mail via SMTP.
// mudar caso for para prod, aqui tem rate limit, mas por 
// agora serve, só demonstracao
export const sendPasswordResetEmail = async (to, name, code) => {
  await transporter.sendMail({
    from: process.env.MAIL_FROM || '"Checkop" <no-reply@checkop.com>',
    to,
    subject: 'Checkop - Código de redefinição de senha',
    text:
      `Olá, ${name}!\n\n` +
      `Recebemos uma solicitação para redefinir a senha da sua conta Checkop.\n\n` +
      `Seu código de verificação é: ${code}\n\n` +
      `Esse código expira em 10 minutos.\n\n` +
      `Se você não solicitou essa redefinição, ignore este e-mail.`,
    html:
      `<p>Olá, <strong>${name}</strong>!</p>` +
      `<p>Recebemos uma solicitação para redefinir a senha da sua conta Checkop.</p>` +
      `<p>Seu código de verificação é:</p>` +
      `<p style="font-size: 24px; font-weight: bold; letter-spacing: 4px;">${code}</p>` +
      `<p>Esse código expira em <strong>10 minutos</strong>.</p>` +
      `<p>Se você não solicitou essa redefinição, ignore este e-mail.</p>`,
  });
};

export default transporter;