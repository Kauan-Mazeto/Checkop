import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';

// RF-22 - e-mail ao terminar uma varredura.

let scanRow;
const sent = [];

const prismaMock = {
  scan: { findUnique: mock.fn(async () => scanRow) },
  finding: {
    groupBy: mock.fn(async () => [
      { severity: 'CRITICAL', _count: { _all: 1 } },
      { severity: 'LOW', _count: { _all: 2 } },
    ]),
  },
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const realMailer = await import('../lib/mailer.js');
mock.module(new URL('../lib/mailer.js', import.meta.url).href, {
  namedExports: {
    ...realMailer,
    isMailConfigured: () => Boolean(process.env.SMTP_HOST),
    sendScanFinishedEmail: async (to, data) => sent.push({ to, data }),
  },
});

const { notifyScanFinished } = await import('../lib/scan_notifications.js');
const { buildScanFinishedEmail } = realMailer;

beforeEach(() => {
  sent.length = 0;
  process.env.SMTP_HOST = 'smtp.teste';
  process.env.APP_URL = 'http://localhost:4200/';
  scanRow = {
    id: 's1',
    targetUrl: 'http://localhost:3000',
    objective: 'SQL_INJECTION',
    status: 'COMPLETED',
    user: { name: 'Ana', email: 'ana@x.com', notifyScanEmail: true },
  };
});

test('avisa o dono com a contagem por severidade e o link da varredura', async () => {
  assert.equal(await notifyScanFinished('s1'), true);
  assert.equal(sent[0].to, 'ana@x.com');
  assert.deepEqual(sent[0].data.counts, { CRITICAL: 1, LOW: 2 });
  assert.equal(sent[0].data.link, 'http://localhost:4200/scans/s1');
});

test('quem desligou a notificação não recebe', async () => {
  scanRow.user.notifyScanEmail = false;
  assert.equal(await notifyScanFinished('s1'), false);
  assert.equal(sent.length, 0);
});

test('sem SMTP configurado, pula sem erro', async () => {
  delete process.env.SMTP_HOST;
  assert.equal(await notifyScanFinished('s1'), false);
  assert.equal(sent.length, 0);
});

test('assunto destaca falhas críticas e altas; falha da varredura tem outro texto', () => {
  const ok = buildScanFinishedEmail({ name: 'Ana', targetUrl: 'http://a', objectiveLabel: 'SQLi', status: 'COMPLETED', counts: { CRITICAL: 1, HIGH: 2 }, link: 'http://x' });
  assert.match(ok.subject, /3 falha\(s\) crítica\(s\) ou alta\(s\)/);
  const failed = buildScanFinishedEmail({ name: 'Ana', targetUrl: 'http://a', objectiveLabel: 'SQLi', status: 'FAILED', counts: {}, link: 'http://x' });
  assert.match(failed.subject, /não pôde ser concluída/);
});

test('nome e alvo não entram crus no HTML do e-mail', () => {
  const { html } = buildScanFinishedEmail({
    name: '<script>alert(1)</script>',
    targetUrl: 'http://a/"><img src=x>',
    objectiveLabel: 'SQLi',
    status: 'COMPLETED',
    counts: {},
    link: 'http://x',
  });
  assert.equal(html.includes('<script>'), false);
  assert.equal(html.includes('<img'), false);
  assert.match(html, /&lt;script&gt;/);
});
