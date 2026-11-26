import prisma from './prisma.js';
import { isMailConfigured, sendScanFinishedEmail } from './mailer.js';
import { SCAN_OBJECTIVES } from '../constants/scan_objectives.js';
import { groupFindings } from './finding_groups.js';

// RF-22 - avisa o dono da varredura por e-mail quando ela termina (concluída ou
// com falha), destacando falhas críticas e altas. Só a contagem por severidade
// vai no e-mail: detalhes técnicos ficam na plataforma, atrás do login.

/** Endereço do front para o link do e-mail. */
export const appUrl = () => (process.env.APP_URL?.trim() || 'http://localhost:4200').replace(/\/+$/, '');

export const notifyScanFinished = async (scanId) => {
  try {
    if (!isMailConfigured()) return false;

    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      select: {
        id: true,
        targetUrl: true,
        objective: true,
        status: true,
        user: { select: { name: true, email: true, notifyScanEmail: true } },
      },
    });
    if (!scan?.user?.notifyScanEmail) return false;

    // contagem por FALHA (como na tela), não por local: o mesmo cabeçalho em 8 páginas conta 1
    const rows = await prisma.finding.findMany({
      where: { scanId },
      select: { title: true, severity: true, cvssScore: true },
    });
    const counts = {};
    for (const group of groupFindings(rows)) counts[group.severity] = (counts[group.severity] ?? 0) + 1;

    await sendScanFinishedEmail(scan.user.email, {
      name: scan.user.name,
      targetUrl: scan.targetUrl,
      objectiveLabel: SCAN_OBJECTIVES[scan.objective]?.label ?? scan.objective,
      status: scan.status,
      counts,
      link: `${appUrl()}/scans/${scan.id}`,
    });
    return true;
  } catch (error) {
    // a notificação nunca derruba a varredura: só registra
    console.error(`[scan ${scanId}] falha ao enviar notificação por e-mail:`, error.message ?? error);
    return false;
  }
};
