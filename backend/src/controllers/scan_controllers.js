import prisma from '../lib/prisma.js';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';
import { runNucleiScan, runZapScan, runSubdomainEnum, SecurityEngineError } from '../lib/py/security_engine_client.js';
import { serializeFindings } from '../lib/py/finding_serializer.js';
import { SCAN_OBJECTIVES } from '../constants/scan_objectives.js';

const serializeIps = (ips) => ips.join(',');
const deserializeIps = (value) => (value ? value.split(',') : []);

// RF-46
const dedupeFindings = (findings) => {
  const seen = new Map();
  for (const finding of findings) {
    const url = finding.affectedUrl?.toLowerCase();
    const fallback = finding.rawRequest ?? finding.description ?? finding.id ?? Math.random();
    const key = `${finding.title?.toLowerCase()}::${url ?? fallback}`;
    if (!seen.has(key)) seen.set(key, finding);
  }
  return [...seen.values()];
};

const createScan = async (req, res) => {
  try {
    const { targetUrl, objective } = req.body;

    let detection;
    try {
      detection = await detectEnvironment(targetUrl);
    } catch (err) {
      if (err instanceof ScanValidationError) {
        return res.status(400).json({ error: err.message });
      }
      throw err;
    }

    const { environment, resolvedIps, suspicious } = detection;
    const safeMode = environment === 'PRODUCTION';

    const scan = await prisma.scan.create({
      data: {
        targetUrl,
        objective,
        environment,
        safeMode,
        resolvedIps: serializeIps(resolvedIps),
        suspiciousEnvironment: suspicious,
        userId: req.userId,
        authorizationConfirmedAt: new Date(),
        authorizationIp: req.ip,
      },
    });

    return res.status(201).json({
      message: 'Varredura registrada com sucesso.',
      scan: {
        id: scan.id,
        targetUrl: scan.targetUrl,
        objective: scan.objective,
        environment: scan.environment,
        safeMode: scan.safeMode,
        status: scan.status,
        suspiciousEnvironment: scan.suspiciousEnvironment,
        resolvedIps: deserializeIps(scan.resolvedIps),
        createdAt: scan.createdAt,
      },
    });
  } catch (error) {
    console.error('Erro ao criar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao registrar varredura.' });
  }
};

const listScans = async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        targetUrl: true,
        environment: true,
        safeMode: true,
        status: true,
        suspiciousEnvironment: true,
        resolvedIps: true,
        createdAt: true,
        startedAt: true,
        finishedAt: true,
      },
    });

    const serialized = scans.map((scan) => ({
      ...scan,
      resolvedIps: deserializeIps(scan.resolvedIps),
    }));

    return res.status(200).json({ scans: serialized });
  } catch (error) {
    console.error('Erro ao listar varreduras:', error);
    return res.status(500).json({ error: 'Erro interno ao listar varreduras.' });
  }
};

const listSuspiciousScans = async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: {
        userId: req.userId,
        suspiciousEnvironment: true,
      },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        targetUrl: true,
        resolvedIps: true,
        environment: true,
        createdAt: true,
      },
    });

    const serialized = scans.map((scan) => ({
      ...scan,
      resolvedIps: deserializeIps(scan.resolvedIps),
    }));

    return res.status(200).json({ scans: serialized });
  } catch (error) {
    console.error('Erro ao listar varreduras suspeitas:', error);
    return res.status(500).json({ error: 'Erro interno ao listar varreduras suspeitas.' });
  }
};

const getScanById = async (req, res) => {
  try {
    const findings = await prisma.finding.findMany({
      where: { scanId: req.resource.id },
    });

    return res.status(200).json({
      scan: {
        ...req.resource,
        resolvedIps: deserializeIps(req.resource.resolvedIps),
        findings: serializeFindings(findings, { safeMode: req.resource.safeMode }),
      },
    });
  } catch (error) {
    console.error('Erro ao buscar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar varredura.' });
  }
};

// dispara a execução real da varredura (RF-10) contra o alvo já registrado e
// validado em createScan. Idempotente contra reexecução: só roda se o status
// ainda for PENDING ou FAILED (evita disparar duas vezes a mesma varredura
// em paralelo, ou repetir uma já concluída sem intenção).
const runScan = async (req, res) => {
  const scan = req.resource;

  if (scan.status === 'RUNNING') {
    return res.status(409).json({ error: 'Esta varredura já está em execução.' });
  }
  if (scan.status === 'COMPLETED') {
    return res.status(409).json({ error: 'Esta varredura já foi concluída.' });
  }

  try {
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'RUNNING', startedAt: new Date() },
    });

    const config = SCAN_OBJECTIVES[scan.objective] ?? SCAN_OBJECTIVES.FULL_SCAN;
    const jobs = [];

    if (config.engines.includes('NUCLEI') && config.nuclei) {
      jobs.push(
        runNucleiScan({
          targetUrl: scan.targetUrl,
          safeMode: scan.safeMode,
          rateLimit: 10,
          tags: config.nuclei.tags,
        }).then((r) => ({ tool: 'NUCLEI', ...r }))
      );
    }

    if (config.engines.includes('ZAP') && config.zap) {
      jobs.push(
        runZapScan({
          targetUrl: scan.targetUrl,
          safeMode: scan.safeMode,
          scannerIds: config.zap.scannerIds,
        }).then((r) => ({ tool: 'ZAP', ...r }))
      );
    }

    if (config.engines.includes('SUBFINDER')) {
      const { hostname } = new URL(scan.targetUrl);
      jobs.push(
        runSubdomainEnum({ domain: hostname }).then((r) => ({ tool: 'SUBFINDER', ...r }))
      );
    }

    const outcomes = await Promise.allSettled(jobs);

    const rawFindings = [];
    const toolErrors = [];

    outcomes.forEach((outcome) => {
      if (outcome.status === 'fulfilled') {
        rawFindings.push(...outcome.value.findings);
      } else {
        toolErrors.push(outcome.reason?.message ?? 'Erro desconhecido em uma das ferramentas.');
        console.error('Falha em uma das ferramentas de varredura:', outcome.reason);
      }
    });

    if (outcomes.length > 0 && outcomes.every((o) => o.status === 'rejected')) {
      throw outcomes[0].reason;
    }

    const allFindings = dedupeFindings(rawFindings);

    await prisma.$transaction([
      prisma.finding.createMany({
        data: allFindings.map((finding) => ({ ...finding, scanId: scan.id })),
      }),
      prisma.scan.update({
        where: { id: scan.id },
        data: { status: 'COMPLETED', finishedAt: new Date() },
      }),
    ]);

    const findings = await prisma.finding.findMany({ where: { scanId: scan.id } });

    return res.status(200).json({
      message: 'Varredura concluída.',
      scan: { id: scan.id, status: 'COMPLETED', objective: scan.objective },
      toolErrors,
      findings: serializeFindings(findings, { safeMode: scan.safeMode }),
    });
  } catch (error) {
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'FAILED', finishedAt: new Date() },
    });

    if (error instanceof SecurityEngineError) {
      return res.status(error.status ?? 502).json({ error: error.message });
    }

    console.error('Erro ao executar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao executar varredura.' });
  }
};

export default { createScan, listScans, listSuspiciousScans, getScanById, runScan };