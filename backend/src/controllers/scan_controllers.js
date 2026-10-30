import prisma from '../lib/prisma.js';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';
import { runNucleiScan, runZapScan, runSubdomainEnum, SecurityEngineError } from '../lib/py/security_engine_client.js';
import { serializeFindings } from '../lib/py/finding_serializer.js';
import { SCAN_OBJECTIVES } from '../constants/scan_objectives.js';

const serializeIps = (ips) => ips.join(',');
const deserializeIps = (value) => (value ? value.split(',') : []);

// RF-46 - deduplicação de achados.
// Dois achados são "o mesmo" quando têm a mesma CLASSE de vulnerabilidade e a mesma
// URL (sem query string). Assim, ZAP e Nuclei apontando o mesmo SQLi em /api/busca
// viram um único registro, mesmo que cada um dê um nome diferente ao achado.
const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const FILL_FIELDS = ['description', 'cveId', 'cvssScore', 'rawRequest', 'rawResponse', 'remediation', 'owaspUrl'];

const VULN_CLASSES = [
  ['sqli', /sql[\s-]*inj|sqli/i],
  ['xss', /xss|cross[\s-]*site[\s-]*scripting/i],
  ['csrf', /csrf|cross[\s-]*site[\s-]*request[\s-]*forgery/i],
  ['ssrf', /ssrf|server[\s-]*side[\s-]*request/i],
  ['open-redirect', /redirect/i],
  ['path-traversal', /path[\s-]*traversal|\blfi\b|local[\s-]*file/i],
  ['rce', /\brce\b|remote[\s-]*code|command[\s-]*inj/i],
];

const classifyFinding = (finding) => {
  const title = (finding.title ?? '').trim();
  for (const [name, pattern] of VULN_CLASSES) {
    if (pattern.test(title)) return name;
  }
  return title.toLowerCase();
};

const normalizeUrl = (value) => {
  if (!value) return null;
  try {
    const url = new URL(value);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    return `${url.protocol}//${url.host}${path}`.toLowerCase();
  } catch {
    return String(value).toLowerCase(); // ex.: Subfinder devolve só o host
  }
};

const dedupeFindings = (findings) => {
  const groups = new Map();

  for (const finding of findings) {
    const where = normalizeUrl(finding.affectedUrl) ?? finding.rawRequest ?? finding.description ?? '';
    const key = `${classifyFinding(finding)}::${where}`;

    if (!groups.has(key)) {
      groups.set(key, { best: finding, rest: [], tools: new Set([finding.tool]) });
      continue;
    }

    const group = groups.get(key);
    group.tools.add(finding.tool);

    const rank = (f) => [SEVERITY_RANK[f.severity] ?? 0, f.cvssScore ?? 0];
    const [newSev, newCvss] = rank(finding);
    const [bestSev, bestCvss] = rank(group.best);

    if (newSev > bestSev || (newSev === bestSev && newCvss > bestCvss)) {
      group.rest.push(group.best);
      group.best = finding; // mantém o registro mais grave
    } else {
      group.rest.push(finding);
    }
  }

  return [...groups.values()].map(({ best, rest, tools }) => {
    const merged = { ...best };

    // completa campos vazios com o que as outras ferramentas trouxeram
    for (const other of rest) {
      for (const field of FILL_FIELDS) {
        if (merged[field] == null && other[field] != null) merged[field] = other[field];
      }
    }

    if (tools.size > 1) {
      const others = [...tools].filter((tool) => tool !== best.tool).join(', ');
      merged.description = `${merged.description ?? ''}\n\nTambém detectado por: ${others}.`.trim();
    }

    return merged;
  });
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

const executeScan = async (scan, runOptions = {}) => {
  try {
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
          auth: runOptions.auth,
          useAjaxSpider: runOptions.useAjaxSpider,
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
    outcomes.forEach((outcome) => {
      if (outcome.status === 'fulfilled') {
        rawFindings.push(...outcome.value.findings);
      } else {
        // falha parcial: uma ferramenta caiu, mas as outras continuam valendo
        console.error(`[scan ${scan.id}] falha em uma ferramenta:`, outcome.reason?.message ?? outcome.reason);
      }
    });

    // se TODAS as ferramentas falharam, a varredura não aconteceu de verdade
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

    console.log(`[scan ${scan.id}] concluída com ${allFindings.length} achado(s).`);
  } catch (error) {
    console.error(`[scan ${scan.id}] falhou:`, error);
    try {
      await prisma.scan.update({
        where: { id: scan.id },
        data: { status: 'FAILED', finishedAt: new Date() },
      });
    } catch (updateError) {
      console.error(`[scan ${scan.id}] não foi possível marcar como FAILED:`, updateError);
    }
  }
};

// Dispara a varredura (RF-10) e responde NA HORA com 202. O trabalho pesado
// roda em segundo plano; o front acompanha pelo GET /api/scans/:id.
const runScan = async (req, res) => {
  try {
    const scan = req.resource;
    const { auth, useAjaxSpider } = req.body;

    // "reserva" a varredura de forma atômica: só uma requisição consegue virar
    // RUNNING (evita duplo clique / duas execuções em paralelo da mesma varredura).
    const claimed = await prisma.scan.updateMany({
      where: { id: scan.id, status: { in: ['PENDING', 'FAILED'] } },
      data: { status: 'RUNNING', startedAt: new Date(), finishedAt: null },
    });

    if (claimed.count === 0) {
      const current = await prisma.scan.findUnique({ where: { id: scan.id } });
      const message =
        current?.status === 'COMPLETED'
          ? 'Esta varredura já foi concluída.'
          : 'Esta varredura já está em execução.';
      return res.status(409).json({ error: message });
    }

    executeScan(scan, { auth, useAjaxSpider });

    return res.status(202).json({
      message: 'Varredura iniciada. Acompanhe o status em GET /api/scans/:id.',
      scan: { id: scan.id, status: 'RUNNING', objective: scan.objective },
    });
  } catch (error) {
    console.error('Erro ao iniciar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao iniciar varredura.' });
  }
};

export default { createScan, listScans, listSuspiciousScans, getScanById, runScan };