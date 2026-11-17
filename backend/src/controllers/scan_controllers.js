import prisma from '../lib/prisma.js';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';
import { runNucleiScan, runZapScan, runSubdomainEnum, cancelEngineJob, SecurityEngineError } from '../lib/py/security_engine_client.js';
import { serializeFindings } from '../lib/py/finding_serializer.js';
import { translateFindings, warmTranslations } from '../lib/finding_translation.js';
import { groupFindings } from '../lib/finding_groups.js';
import { EXPORT_FORMATS, exportFileName, exportJson, findingsCsv, scansCsv } from '../lib/scan_export.js';
import { getDomain } from 'tldts';
import { SCAN_OBJECTIVES, filterFindingsByObjective, listObjectives } from '../constants/scan_objectives.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';
import { findVerifiedTargetForUrl, refreshTargetVerification } from '../lib/target_ownership.js';
import { SEVERITY_RANK, findingKey } from '../lib/finding_identity.js';
import { compareFindings } from '../lib/scan_compare.js';
import { notifyScanFinished } from '../lib/scan_notifications.js';
import { DAILY_LIMIT_CODE, PREMIUM_REQUIRED_CODE, isObjectiveAllowed, planRules, startOfToday } from '../constants/plans.js';

const serializeIps = (ips) => ips.join(',');
const deserializeIps = (value) => (value ? value.split(',') : []);

// RF-46 - deduplicação de achados.
// Dois achados são "o mesmo" quando têm a mesma CLASSE de vulnerabilidade e a mesma
// URL (sem query string). Assim, ZAP e Nuclei apontando o mesmo SQLi em /api/busca
// viram um único registro, mesmo que cada um dê um nome diferente ao achado.
const FILL_FIELDS = ['description', 'cveId', 'cvssScore', 'rawRequest', 'rawResponse', 'remediation', 'owaspUrl'];

const SEVERITY_BADGE = {
  CRITICAL: { label: 'Crítico', color: 'red' },
  HIGH: { label: 'Alto', color: 'red' },
  MEDIUM: { label: 'Médio', color: 'yellow' },
  LOW: { label: 'Baixo', color: 'blue' },
  INFO: { label: 'Informativo', color: 'blue' },
};

// Monta o resumo de alto nível de um scan (espec.txt, seção 2.2):
// badge colorido, veredito em uma frase e contagem por severidade.
const buildScanSummary = (findings) => {
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  if (findings.length === 0) {
    return {
      badge: { label: 'Nenhum achado', color: 'green' },
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

const dedupeFindings = (findings) => {
  const groups = new Map();

  for (const finding of findings) {
    const key = findingKey(finding);

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

const ACTIVE_SCAN_REQUIRED_RESPONSE = Object.freeze({
  error:
    'Este objetivo só detecta falhas enviando ataques ao site. Autorize a varredura ativa (activeScanConfirmed e hostingTermsConfirmed) para executá-lo.',
  code: 'ACTIVE_SCAN_REQUIRED',
});

// ---------- regras do plano (constants/plans.js) ----------

const OBJECTIVE_LOCKED_RESPONSE = Object.freeze({
  error: 'No plano Free a varredura é sempre o scan básico. Escolher o tipo de teste é um recurso Premium.',
  code: PREMIUM_REQUIRED_CODE,
});

const HISTORY_LOCKED_RESPONSE = Object.freeze({
  error: 'No plano Free só a varredura mais recente fica disponível. O histórico completo é um recurso Premium.',
  code: PREMIUM_REQUIRED_CODE,
});

const dailyLimitResponse = (limit) => ({
  error: `Seu plano permite ${limit} varredura(s) por dia e o limite de hoje já foi usado. Volte amanhã ou conheça o Premium.`,
  code: DAILY_LIMIT_CODE,
});

// ids das varreduras que o plano deixa ver; null = todas
const visibleScanIds = async (req) => {
  const { visibleScans } = planRules(req.userPlan);
  if (visibleScans === null) return null;
  const latest = await prisma.scan.findMany({
    where: { userId: req.userId },
    orderBy: { createdAt: 'desc' },
    take: visibleScans,
    select: { id: true },
  });
  return latest.map((scan) => scan.id);
};

const getObjectives = (req, res) => res.status(200).json({ objectives: listObjectives() });

const createScan = async (req, res) => {
  try {
    const { targetUrl } = req.body;
    const rules = planRules(req.userPlan);
    const objective = req.body.objective ?? rules.defaultObjective;

    if (!isObjectiveAllowed(req.userPlan, objective)) {
      return res.status(403).json(OBJECTIVE_LOCKED_RESPONSE);
    }

    if (rules.dailyScanLimit !== null) {
      const createdToday = await prisma.scan.count({
        where: { userId: req.userId, createdAt: { gte: startOfToday() } },
      });
      if (createdToday >= rules.dailyScanLimit) {
        return res.status(429).json(dailyLimitResponse(rules.dailyScanLimit));
      }
    }

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
      // a prova é conferida ao vivo também na criação, não só na execução:
      // removeu o TXT/arquivo/tag depois de verificar, perde o acesso na hora
      if (target && !(await refreshTargetVerification(target))) target = null;
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
    const { visibleScans } = planRules(req.userPlan);
    const scans = await prisma.scan.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
      // Free enxerga só a(s) mais recente(s)
      ...(visibleScans !== null && { take: visibleScans }),
      select: {
        id: true,
        targetUrl: true,
        objective: true,
        environment: true,
        safeMode: true,
        status: true,
        suspiciousEnvironment: true,
        resolvedIps: true,
        createdAt: true,
        startedAt: true,
        finishedAt: true,
        _count: { select: { findings: true } },
      },
    });

    const serialized = scans.map(({ _count, ...scan }) => ({
      ...scan,
      objectiveLabel: SCAN_OBJECTIVES[scan.objective]?.label ?? scan.objective,
      findingsCount: _count.findings,
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
    // os gráficos usam só as varreduras que o plano deixa ver
    const ids = await visibleScanIds(req);
    const scanWhere = { userId: req.userId, ...(ids && { id: { in: ids } }) };

    const scans = await prisma.scan.findMany({
      where: scanWhere,
      select: { id: true, status: true, objective: true, environment: true, createdAt: true },
    });

    const findings = await prisma.finding.findMany({
      where: { scan: scanWhere },
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
    const ids = await visibleScanIds(req);
    if (ids && !ids.includes(req.resource.id)) {
      return res.status(403).json(HISTORY_LOCKED_RESPONSE);
    }

    const findings = await prisma.finding.findMany({
      where: { scanId: req.resource.id },
    });
    const localized = await translateFindings(findings, req.userLanguage);
    // uma entrada por falha, com os locais onde ela aparece
    const grouped = groupFindings(
      serializeFindings(localized, { safeMode: req.resource.safeMode, plan: req.userPlan, role: req.userRole }),
    );

    return res.status(200).json({
      scan: {
        ...req.resource,
        resolvedIps: deserializeIps(req.resource.resolvedIps),
        objectiveLabel: SCAN_OBJECTIVES[req.resource.objective]?.label ?? req.resource.objective,
        engineWarnings: req.resource.engineWarnings ? JSON.parse(req.resource.engineWarnings) : [],
        summary: buildScanSummary(grouped),
        plan: req.userPlan,
        role: req.userRole,
        language: req.userLanguage,
        findings: grouped,
      },
    });
  } catch (error) {
    console.error('Erro ao buscar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar varredura.' });
  }
};

// RF-19 - compara esta varredura com uma anterior do MESMO alvo e do MESMO
// objetivo (objetivos diferentes testam coisas diferentes: comparar um scan de
// SQLi com um de cabeçalhos diria que tudo foi "corrigido"). Sem ?with=, usa a
// varredura concluída imediatamente anterior. Comparar exige histórico (Premium).
const SCAN_SUMMARY_FIELDS = { id: true, targetUrl: true, objective: true, createdAt: true, finishedAt: true, status: true, safeMode: true };

const compareScans = async (req, res) => {
  try {
    if (planRules(req.userPlan).visibleScans !== null) {
      return res.status(403).json({
        error: 'Comparar varreduras usa o histórico completo, um recurso Premium.',
        code: PREMIUM_REQUIRED_CODE,
      });
    }

    const current = req.resource;
    if (current.status !== 'COMPLETED') {
      return res.status(409).json({ error: 'A varredura ainda não terminou; compare quando ela estiver concluída.' });
    }

    const sameTarget = {
      userId: req.userId,
      targetUrl: current.targetUrl,
      objective: current.objective,
      status: 'COMPLETED',
      id: { not: current.id },
    };

    // varreduras que podem ser escolhidas para comparar (mais recentes primeiro)
    const candidates = await prisma.scan.findMany({
      where: sameTarget,
      orderBy: { createdAt: 'desc' },
      take: 20,
      select: SCAN_SUMMARY_FIELDS,
    });

    const withId = typeof req.query.with === 'string' ? req.query.with : null;
    const base = withId
      ? candidates.find((scan) => scan.id === withId)
      : candidates.find((scan) => scan.createdAt < current.createdAt) ?? null;

    if (withId && !base) {
      return res.status(404).json({ error: 'Varredura para comparação não encontrada (precisa ser do mesmo alvo e do mesmo tipo de teste).' });
    }

    const pick = (scan) => ({
      id: scan.id,
      createdAt: scan.createdAt,
      finishedAt: scan.finishedAt,
      objective: scan.objective,
      objectiveLabel: SCAN_OBJECTIVES[scan.objective]?.label ?? scan.objective,
    });

    if (!base) {
      return res.status(200).json({ current: pick(current), base: null, candidates: candidates.map(pick) });
    }

    const [previousFindings, currentFindings] = await Promise.all([
      prisma.finding.findMany({ where: { scanId: base.id } }),
      prisma.finding.findMany({ where: { scanId: current.id } }),
    ]);
    const diff = compareFindings(previousFindings, currentFindings);

    // traduz depois de comparar: a identidade do achado usa o texto original
    const persistentFindings = diff.persistent.map((item) => item.finding);
    const localized = await translateFindings([...diff.added, ...diff.fixed, ...persistentFindings], req.userLanguage);
    const added = localized.slice(0, diff.added.length);
    const fixed = localized.slice(diff.added.length, diff.added.length + diff.fixed.length);
    const persistent = localized.slice(diff.added.length + diff.fixed.length);

    // cada achado segue o Modo Seguro da varredura de onde veio (RF-08)
    const serializeFrom = (scan) => (list) => serializeFindings(list, { safeMode: scan.safeMode, plan: req.userPlan, role: req.userRole });

    return res.status(200).json({
      current: pick(current),
      base: pick(base),
      candidates: candidates.map(pick),
      summary: diff.summary,
      added: serializeFrom(current)(added),
      fixed: serializeFrom(base)(fixed),
      persistent: diff.persistent.map((item, index) => ({
        ...serializeFrom(current)([persistent[index]])[0],
        previousSeverity: item.previousSeverity,
        trend: item.trend,
      })),
    });
  } catch (error) {
    console.error('Erro ao comparar varreduras:', error);
    return res.status(500).json({ error: 'Erro interno ao comparar varreduras.' });
  }
};

// varreduras em execução cujo cancelamento foi pedido; ao terminar, viram CANCELED
const cancelRequested = new Set();

const executeScan = async (scan, runOptions = {}) => {
  try {
    const config = SCAN_OBJECTIVES[scan.objective] ?? SCAN_OBJECTIVES.FULL_SCAN;
    const jobs = [];
    const warnings = [];

    if (config.engines.includes('NUCLEI') && config.nuclei) {
      // activeTags (ex.: tentativa de login padrão) só com ataque autorizado
      const extraTags = runOptions.activeScan ? (config.nuclei.activeTags ?? []) : [];
      jobs.push(
        runNucleiScan({
          targetUrl: scan.targetUrl,
          // sem opt-in de ataque, os templates intrusivos ficam de fora (RF-52)
          safeMode: !runOptions.activeScan,
          rateLimit: 10,
          tags: [...config.nuclei.tags, ...extraTags],
          jobId: scan.id,
        }).then((r) => ({ tool: 'NUCLEI', ...r }))
      );
    }

    if (config.engines.includes('ZAP') && config.zap) {
      jobs.push(
        runZapScan({
          targetUrl: scan.targetUrl,
          safeMode: scan.safeMode,
          activeScan: runOptions.activeScan === true,
          scannerIds: config.zap.activeScannerIds,
          auth: runOptions.auth,
          useAjaxSpider: runOptions.useAjaxSpider,
          jobId: scan.id,
        }).then((r) => ({ tool: 'ZAP', ...r }))
      );
    }

    if (config.engines.includes('SUBFINDER')) {
      // subdomínios são do domínio registrável (www.loja.com.br -> loja.com.br)
      const domain = getDomain(new URL(scan.targetUrl).hostname);
      if (domain && !cancelRequested.has(scan.id)) {
        jobs.push(runSubdomainEnum({ domain }).then((r) => ({ tool: 'SUBFINDER', ...r })));
      } else if (!domain) {
        warnings.push('Enumeração de subdomínios não se aplica a localhost ou endereço IP.');
      }
    }

    const outcomes = await Promise.allSettled(jobs);

    const rawFindings = [];
    outcomes.forEach((outcome) => {
      if (outcome.status === 'fulfilled') {
        rawFindings.push(...outcome.value.findings);
        warnings.push(...(outcome.value.warnings ?? []));
      } else {
        // mensagem genérica ao usuário; o detalhe técnico fica só no log (RNF-25)
        warnings.push('Uma das ferramentas de varredura não pôde ser executada; o resultado pode estar incompleto.');
        // falha parcial: uma ferramenta caiu, mas as outras continuam valendo
        console.error(`[scan ${scan.id}] falha em uma ferramenta:`, outcome.reason?.message ?? outcome.reason);
      }
    });

    // se TODAS as ferramentas falharam, a varredura não aconteceu de verdade
    if (outcomes.length > 0 && outcomes.every((o) => o.status === 'rejected')) {
      throw outcomes[0].reason;
    }

    const canceled = cancelRequested.has(scan.id);
    const allFindings = dedupeFindings(filterFindingsByObjective(rawFindings, scan.objective));
    // traduz já para o idioma do dono: a página abre com o texto pronto
    await warmTranslations(allFindings, scan.userId);

    await prisma.$transaction([
      prisma.finding.createMany({
        data: allFindings.map((finding) => ({ ...finding, scanId: scan.id })),
      }),
      prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: canceled ? 'CANCELED' : 'COMPLETED',
          finishedAt: new Date(),
          engineWarnings: warnings.length ? JSON.stringify([...new Set(warnings)]) : null,
        },
      }),
    ]);

    console.log(`[scan ${scan.id}] ${canceled ? 'cancelada' : 'concluída'} com ${allFindings.length} achado(s).`);
  } catch (error) {
    const canceled = cancelRequested.has(scan.id);
    console.error(`[scan ${scan.id}] ${canceled ? 'cancelada sem resultado' : 'falhou'}:`, error);
    try {
      await prisma.scan.update({
        where: { id: scan.id },
        data: { status: canceled ? 'CANCELED' : 'FAILED', finishedAt: new Date() },
      });
    } catch (updateError) {
      console.error(`[scan ${scan.id}] não foi possível marcar como FAILED:`, updateError);
    }
  }
  cancelRequested.delete(scan.id);
  // RF-22: avisa o dono por e-mail (concluída ou com falha); nunca lança erro
  await notifyScanFinished(scan.id);
};

// Painel > Exportar: todas as varreduras da conta em CSV (achados ou varreduras)
// ou JSON. Premium. Achados seguem as mesmas regras da tela: Modo Seguro de
// cada varredura, plano, perfil e idioma do usuário.
const EXPORT_MAX_SCANS = 500;

const exportScans = async (req, res) => {
  try {
    if (!planRules(req.userPlan).canExportReports) {
      return res.status(403).json({ error: 'Exportar relatórios é um recurso Premium.', code: PREMIUM_REQUIRED_CODE });
    }

    const format = typeof req.query.format === 'string' ? req.query.format : 'json';
    if (!EXPORT_FORMATS[format]) {
      return res.status(400).json({ error: `Formato inválido. Use: ${Object.keys(EXPORT_FORMATS).join(', ')}.` });
    }

    const scans = await prisma.scan.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
      take: EXPORT_MAX_SCANS,
      include: { findings: true },
    });

    // traduz tudo de uma vez (uma chamada ao motor) e devolve cada achado à sua varredura
    const localized = await translateFindings(scans.flatMap((scan) => scan.findings), req.userLanguage);
    let offset = 0;
    const prepared = scans.map((scan) => {
      const own = localized.slice(offset, offset + scan.findings.length);
      offset += scan.findings.length;
      const serialized = serializeFindings(own, { safeMode: scan.safeMode, plan: req.userPlan, role: req.userRole });
      // CSV: uma linha por local; JSON: uma entrada por falha com os locais dentro
      return { ...scan, findings: format === 'json' ? groupFindings(serialized) : serialized };
    });

    await logAudit(req, { action: AUDIT_ACTIONS.REPORT_EXPORTED, resourceType: 'scan', details: { format, scans: scans.length } });

    const { type } = EXPORT_FORMATS[format];
    const body =
      format === 'findings-csv' ? findingsCsv(prepared)
        : format === 'scans-csv' ? scansCsv(prepared)
          : JSON.stringify(exportJson(prepared, { language: req.userLanguage }), null, 2);

    res.setHeader('Content-Type', type);
    res.setHeader('Content-Disposition', `attachment; filename="${exportFileName(format)}"`);
    return res.status(200).send(body);
  } catch (error) {
    console.error('Erro ao exportar varreduras:', error);
    return res.status(500).json({ error: 'Erro interno ao exportar as varreduras.' });
  }
};

// Cancela a varredura: o motor para o Nuclei e o ZAP, que devolvem o que já
// encontraram; executeScan grava esses achados com status CANCELED.
const cancelScan = async (req, res) => {
  try {
    const scan = req.resource;

    if (scan.status === 'PENDING') {
      await prisma.scan.update({ where: { id: scan.id }, data: { status: 'CANCELED', finishedAt: new Date() } });
      await logAudit(req, { action: AUDIT_ACTIONS.SCAN_CANCELED, resourceType: 'scan', resourceId: scan.id });
      return res.status(200).json({ message: 'Varredura cancelada antes de começar.' });
    }

    if (scan.status !== 'RUNNING') {
      return res.status(409).json({ error: 'Só é possível cancelar uma varredura que ainda está em andamento.' });
    }

    cancelRequested.add(scan.id);
    try {
      await cancelEngineJob(scan.id);
    } catch (error) {
      // sem o motor, a varredura termina sozinha e mesmo assim fica como cancelada
      console.error(`[scan ${scan.id}] não foi possível avisar o motor do cancelamento:`, error.message);
    }
    await logAudit(req, { action: AUDIT_ACTIONS.SCAN_CANCELED, resourceType: 'scan', resourceId: scan.id });
    return res.status(202).json({ message: 'Cancelando: as ferramentas estão parando e o que já foi verificado será salvo.' });
  } catch (error) {
    console.error('Erro ao cancelar varredura:', error);
    return res.status(500).json({ error: 'Erro interno ao cancelar a varredura.' });
  }
};

// Dispara a varredura (RF-10) e responde NA HORA com 202. O trabalho pesado
// roda em segundo plano; o front acompanha pelo GET /api/scans/:id.
const runScan = async (req, res) => {
  try {
    const scan = req.resource;
    const { auth, useAjaxSpider, activeScanConfirmed } = req.body;

    // varredura criada no Premium e executada depois de voltar ao Free
    if (!isObjectiveAllowed(req.userPlan, scan.objective)) {
      return res.status(403).json(OBJECTIVE_LOCKED_RESPONSE);
    }

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

    // objetivo que só detecta atacando (ex.: SQLi) sem ataque autorizado daria um
    // falso "nenhuma falha encontrada": melhor recusar e explicar
    if (!activeScan && SCAN_OBJECTIVES[scan.objective]?.requiresActiveScan) {
      return res.status(400).json(ACTIVE_SCAN_REQUIRED_RESPONSE);
    }

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

export default { getObjectives, createScan, listScans, listSuspiciousScans, getScanStats, getScanById, compareScans, runScan, cancelScan, exportScans };