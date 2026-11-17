import nodemailer from 'nodemailer';

let transporter;

const getTransporter = () => {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return transporter;
};

const FROM = () => process.env.MAIL_FROM || '"Checkop" <no-reply@checkop.com>';

/** Sem SMTP configurado, as notificações são simplesmente puladas. */
export const isMailConfigured = () => Boolean(process.env.SMTP_HOST?.trim());

// nome e URL vêm do usuário: nada entra cru no HTML do e-mail
export const escapeHtml = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

export const sendPasswordResetEmail = async (to, name, code) => {
  await getTransporter().sendMail({
    from: FROM(),
    to,
    subject: 'Checkop - Código de redefinição de senha',
    text:
      `Olá, ${name}!\n\n` +
      `Recebemos uma solicitação para redefinir a senha da sua conta Checkop.\n\n` +
      `Seu código de verificação é: ${code}\n\n` +
      `Esse código expira em 10 minutos.\n\n` +
      `Se você não solicitou essa redefinição, ignore este e-mail.`,
    html:
      `<p>Olá, <strong>${escapeHtml(name)}</strong>!</p>` +
      `<p>Recebemos uma solicitação para redefinir a senha da sua conta Checkop.</p>` +
      `<p>Seu código de verificação é:</p>` +
      `<p style="font-size: 24px; font-weight: bold; letter-spacing: 4px;">${escapeHtml(code)}</p>` +
      `<p>Esse código expira em <strong>10 minutos</strong>.</p>` +
      `<p>Se você não solicitou essa redefinição, ignore este e-mail.</p>`,
  });
};

const SEVERITY_LABEL = { CRITICAL: 'Críticas', HIGH: 'Altas', MEDIUM: 'Médias', LOW: 'Baixas', INFO: 'Informativas' };

/** Monta o e-mail de varredura concluída (exportado para teste). */
export const buildScanFinishedEmail = ({ name, targetUrl, objectiveLabel, status, counts, link }) => {
  const failed = status === 'FAILED';
  const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
  const highRisk = (counts.CRITICAL ?? 0) + (counts.HIGH ?? 0);

  const subject = failed
    ? 'Checkop - A varredura não pôde ser concluída'
    : highRisk > 0
      ? `Checkop - ${highRisk} falha(s) crítica(s) ou alta(s) encontrada(s)`
      : 'Checkop - Varredura concluída';

  const headline = failed
    ? 'A varredura não pôde ser concluída. Você pode tentar de novo pela plataforma.'
    : total === 0
      ? 'A varredura terminou sem nenhuma falha encontrada para este tipo de teste.'
      : `A varredura terminou com ${total} falha(s) encontrada(s).`;

  const lines = failed
    ? []
    : Object.entries(SEVERITY_LABEL)
        .filter(([key]) => (counts[key] ?? 0) > 0)
        .map(([key, label]) => `${label}: ${counts[key]}`);

  const text =
    `Olá, ${name}!\n\n${headline}\n\n` +
    `Alvo: ${targetUrl}\nTipo de teste: ${objectiveLabel}\n` +
    (lines.length ? `\n${lines.join('\n')}\n` : '') +
    `\nVer o resultado: ${link}\n\n` +
    'Você recebe este aviso porque ativou as notificações por e-mail. Para desligar, acesse Conta e privacidade.';

  const html =
    `<p>Olá, <strong>${escapeHtml(name)}</strong>!</p>` +
    `<p>${escapeHtml(headline)}</p>` +
    `<p><strong>Alvo:</strong> ${escapeHtml(targetUrl)}<br><strong>Tipo de teste:</strong> ${escapeHtml(objectiveLabel)}</p>` +
    (lines.length ? `<ul>${lines.map((l) => `<li>${escapeHtml(l)}</li>`).join('')}</ul>` : '') +
    `<p><a href="${escapeHtml(link)}">Ver o resultado no Checkop</a></p>` +
    `<p style="color:#666;font-size:12px">Você recebe este aviso porque ativou as notificações por e-mail. Para desligar, acesse Conta e privacidade.</p>`;

  return { subject, text, html };
};

export const sendScanFinishedEmail = async (to, data) => {
  const { subject, text, html } = buildScanFinishedEmail(data);
  await getTransporter().sendMail({ from: FROM(), to, subject, text, html });
};
