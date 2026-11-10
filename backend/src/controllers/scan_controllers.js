import prisma from '../lib/prisma.js';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';
import { runNucleiScan, runZapScan, runSubdomainEnum, SecurityEngineError } from '../lib/py/security_engine_client.js';
import { serializeFindings } from '../lib/py/finding_serializer.js';
import { SCAN_OBJECTIVES } from '../constants/scan_objectives.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';
import { findVerifiedTargetForUrl, refreshTargetVerification } from '../lib/target_ownership.js';

const serializeIps = (ips) => ips.join(',');
const deserializeIps = (value) => (value ? value.split(',') : []);

// RF-46 - deduplicação de achados.
// Dois achados são "o mesmo" quando têm a mesma CLASSE de vulnerabilidade e a mesma
// URL (sem query string). Assim, ZAP e Nuclei apontando o mesmo SQLi em /api/busca
// viram um único registro, mesmo que cada um dê um nome diferente ao achado.
const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const FILL_FIELDS = ['description', 'cveId', 'cvssScore', 'rawRequest', 'rawResponse', 'remediation', 'owaspUrl'];

const SEVERITY_BADGE = {
  CRITICAL: { emoji: '🔴', label: 'Crítico', color: 'red' },
  HIGH: { emoji: '🔴', label: 'Alto', color: 'red' },
  MEDIUM: { emoji: '🟡', label: 'Médio', color: 'yellow' },
  LOW: { emoji: '🔵', label: 'Baixo', color: 'blue' },
  INFO: { emoji: '🔵', label: 'Informativo', color: 'blue' },
};

// Monta o resumo de alto nível de um scan (espec.txt, seção 2.2):
// badge colorido, veredito em uma frase e contagem por severidade.
const buildScanSummary = (findings) => {
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  if (findings.length === 0) {
    return {
      badge: { emoji: '🟢', label: 'Nenhum achado', color: 'green' },
      verdict: 'Nenhuma vulnerabilidade foi identificada nesta varredura.',
      severityCounts,
    };
  }

  let worst = findings[0];
  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
    if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[worst.severity] ?? 0)) worst = f;
  }

  const total = findings.length;
  const verdict =
    worst.severity === 'CRITICAL' || worst.severity === 'HIGH'
      ? `Foram encontradas ${total} falha(s), incluindo pelo menos uma de alto impacto. Correção prioritária recomendada.`
      : worst.severity === 'MEDIUM'
        ? `Foram encontradas ${total} falha(s) de risco moderado. Recomenda-se correção em breve.`
        : `Foram encontradas ${total} falha(s) de baixo risco ou informativas.`;

  return { badge: SEVERITY_BADGE[worst.severity], verdict, severityCounts };
};

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

// B3: domínio público que resolve para IP interno é o padrão de DNS rebinding/SSRF
// contra a infraestrutura do próprio Checkop. O registro fica (auditoria em
// GET /api/scans/suspicious), mas a execução é sempre recusada.
const SUSPICIOUS_TARGET_MESSAGE =
  'Este domínio público resolve para um endereço de rede interna. A varredura foi registrada para auditoria, mas não pode ser executada.';

// B5: o DNS pode mudar entre o cadastro e a execução (ex.: TTL curto apontando
// para 127.0.0.1 depois). Revalida no momento do run. Não elimina 100% a janela,
// porque ZAP e Nuclei resolvem o host por conta própria durante a varredura.
const revalidateTargetBeforeRun = async (scan) => {
  if (scan.suspiciousEnvironment) return SUSPICIOUS_TARGET_MESSAGE;

  let detection;
  try {
    detection = await detectEnvironment(scan.targetUrl);
  } catch (err) {
    if (err instanceof ScanValidationError) return err.message;
    throw err;
  }

  if (!detection.suspicious) return null;

  await prisma.scan.update({
    where: { id: scan.id },
    data: { suspiciousEnvironment: true, resolvedIps: serializeIps(detection.resolvedIps) },
  });
  return SUSPICIOUS_TARGET_MESSAGE;
};

// TCC, seção 9: alvo local/rede privada é ambiente de desenvolvimento e fica isento
const requiresVerifiedTarget = (environment) => environment !== 'DEVELOPMENT';

const TARGET_NOT_VERIFIED_RESPONSE = Object.freeze({
  error: 'Para varrer um site público, cadastre e verifique a propriedade do domínio em /api/targets.',
  code: 'TARGET_NOT_VERIFIED',
});

// Confere de novo, antes de cada execução, que o usuário ainda controla o alvo.
const ensureTargetStillVerified = async (scan) => {
  if (!requiresVerifiedTarget(scan.environment)) return true;

  const target = scan.targetId
    ? await prisma.target.findUnique({ where: { id: scan.targetId } })
    : await findVerifiedTargetForUrl(scan.userId, scan.targetUrl);

  return Boolean(target) && (await refreshTargetVerification(target));
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

    // alvo público (homologação ou produção) só com propriedade comprovada.
    // O suspeito segue para ser registrado (auditoria) e é barrado no run.
    let target = null;
    if (requiresVerifiedTarget(environment) && !suspicious) {
      target = await findVerifiedTargetForUrl(req.userId, targetUrl);
      if (!target) {
        await logAudit(req, {
          action: AUDIT_ACTIONS.SCAN_BLOCKED,
          resourceType: 'scan',
          details: { targetUrl, reason: 'TARGET_NOT_VERIFIED' },
        });
        return res.status(403).json(TARGET_NOT_VERIFIED_RESPONSE);
      }
    }

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
        targetId: target?.id ?? null,
      },
    });

    await logAudit(req, {
      action: AUDIT_ACTIONS.SCAN_CREATED,
      resourceType: 'scan',
      resourceId: scan.id,
      details: { targetUrl, objective: scan.objective, environment, suspicious },
    });

    return res.status(201).json({
      message: suspicious ? SUSPICIOUS_TARGET_MESSAGE : 'Varredura registrada com sucesso.',
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

// Dados agregados de todos os scans do usuário, prontos pra gráfico
// (pizza de severidade, barra por objetivo, linha do tempo, etc.)
const getScanStats = async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { userId: req.userId },
      select: { id: true, status: true, objective: true, environment: true, createdAt: true },
    });

    const findings = await prisma.finding.findMany({
      where: { scan: { userId: req.userId } },
      select: { severity: true, tool: true, owaspUrl: true, status: true, createdAt: true },
    });

    const countBy = (items, key) =>
      items.reduce((acc, item) => {
        const k = item[key] ?? 'UNKNOWN';
        acc[k] = (acc[k] ?? 0) + 1;
        return acc;
      }, {});

    // últimos 30 dias, agrupado por dia (AAAA-MM-DD) — pra gráfico de tendência
    const since = new Date();
    since.setDate(since.getDate() - 30);
    const timelineLast30Days = {};
    for (const f of findings) {
      if (f.createdAt < since) continue;
      const day = f.createdAt.toISOString().slice(0, 10);
      timelineLast30Days[day] = (timelineLast30Days[day] ?? 0) + 1;
    }

    return res.status(200).json({
      scans: {
        total: scans.length,
        byStatus: countBy(scans, 'status'),
        byObjective: countBy(scans, 'objective'),
        byEnvironment: countBy(scans, 'environment'),
      },
      findings: {
        total: findings.length,
        bySeverity: countBy(findings, 'severity'),
        byTool: countBy(findings, 'tool'),
        byOwaspCategory: countBy(findings, 'owaspUrl'),
        byStatus: countBy(findings, 'status'),
        timelineLast30Days,
      },
    });
  } catch (error) {
    console.error('Erro ao gerar estatísticas:', error);
    return res.status(500).json({ error: 'Erro interno ao gerar estatísticas.' });
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
        summary: buildScanSummary(findings),
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
          // sem opt-in de ataque, os templates intrusivos ficam de fora (RF-52)
          safeMode: !runOptions.activeScan,
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
          activeScan: runOptions.activeScan === true,
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
    const { auth, useAjaxSpider, activeScanConfirmed } = req.body;

    const blockReason = await revalidateTargetBeforeRun(scan);
    if (blockReason) {
      await logAudit(req, {
        action: AUDIT_ACTIONS.SCAN_BLOCKED,
        resourceType: 'scan',
        resourceId: scan.id,
        details: { reason: 'UNSAFE_DESTINATION' },
      });
      return res.status(403).json({ error: blockReason });
    }

    if (!(await ensureTargetStillVerified(scan))) {
      await logAudit(req, {
        action: AUDIT_ACTIONS.SCAN_BLOCKED,
        resourceType: 'scan',
        resourceId: scan.id,
        details: { reason: 'TARGET_NOT_VERIFIED' },
      });
      return res.status(403).json(TARGET_NOT_VERIFIED_RESPONSE);
    }

    // Ataque ativo: livre em ambiente local; em alvo público só com o opt-in
    // explícito desta execução (o validator já exigiu a declaração de hospedagem).
    const isPublicTarget = requiresVerifiedTarget(scan.environment);
    const activeScan = !isPublicTarget || activeScanConfirmed === true;

    // "reserva" a varredura de forma atômica: só uma requisição consegue virar
    // RUNNING (evita duplo clique / duas execuções em paralelo da mesma varredura).
    const claimed = await prisma.scan.updateMany({
      where: { id: scan.id, status: { in: ['PENDING', 'FAILED'] } },
      data: {
        status: 'RUNNING',
        startedAt: new Date(),
        finishedAt: null,
        activeScanConfirmedAt: isPublicTarget && activeScan ? new Date() : null,
        activeScanConfirmationIp: isPublicTarget && activeScan ? req.ip : null,
      },
    });

    if (claimed.count === 0) {
      const current = await prisma.scan.findUnique({ where: { id: scan.id } });
      const message =
        current?.status === 'COMPLETED'
          ? 'Esta varredura já foi concluída.'
          : 'Esta varredura já está em execução.';
      return res.status(409).json({ error: message });
    }

    await logAudit(req, {
      action: AUDIT_ACTIONS.SCAN_STARTED,
      resourceType: 'scan',
      resourceId: scan.id,
      details: { environment: scan.environment, objective: scan.objective, activeScan, authenticated: Boolean(auth) },
    });

    executeScan(scan, { auth, useAjaxSpider, activeScan });

    return res.status(202).json({
      message: 'Varredura iniciada. Acompanhe o status em GET /api/scans/:id.',
      scan: { id: scan.id, status: 'RUNNING', objective: scan.objective, activeScan },
    });
  } catch (error) {
    console.error('Erro ao iniciar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao iniciar varredura.' });
  }
};

export default { createScan, listScans, listSuspiciousScans, getScanStats, getScanById, runScan };