// Popula o Checkop com dados de demonstração para a banca, usando a PRÓPRIA API
// (como um usuário de verdade): contas, plano Premium, créditos de IA, varreduras
// reais no laboratório (uma cancelada no meio), triagem de achados e análise de
// código dos dois controllers Java de scripts/demo.
//
// Pré-requisito: tudo no ar (iniciar.cmd): backend :8080, motor :8010, ZAP :8091 e laboratório :3000.
//
// Uso (na raiz do projeto):
//   node scripts/popular-demo.mjs                  tudo (15 a 30 min, por causa das varreduras)
//   node scripts/popular-demo.mjs --so-codigo      só contas + análise de código (poucos minutos)
//   node scripts/popular-demo.mjs --sem-cancelar   pula a varredura completa cancelada
//
// Pode rodar de novo: as contas já existentes só fazem login e ganham mais dados.

import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const API = (process.env.CHECKOP_API ?? 'http://localhost:8080/api').replace(/\/$/, '');
const ENGINE = process.env.CHECKOP_ENGINE ?? 'http://127.0.0.1:8010';
const LAB = process.env.CHECKOP_LAB ?? 'http://localhost:3000';
const args = new Set(process.argv.slice(2));
const SO_CODIGO = args.has('--so-codigo');
const SEM_CANCELAR = args.has('--sem-cancelar');

const DIR = dirname(fileURLToPath(import.meta.url));

// contas da demonstração (troque o perfil na tela "Conta" se quiser mostrar outro painel)
const CONTAS = [
  { name: 'Banca Checkop', email: 'banca@checkop.local', password: 'Banca@2026', role: 'DEV', principal: true },
  { name: 'Estudante Demo', email: 'estudante@checkop.local', password: 'Estudante@2026', role: 'STUDENT' },
];

const FIM = new Set(['COMPLETED', 'FAILED', 'CANCELED']);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const agora = () => new Date().toLocaleTimeString('pt-BR');
const log = (msg) => console.log(`[${agora()}] ${msg}`);
const aviso = (msg) => console.log(`[${agora()}] [!] ${msg}`);

// ---------- HTTP com o cookie de sessão ----------
const cliente = () => {
  let cookie = '';
  const chamar = async (method, path, body, { timeoutMs = 30000 } = {}) => {
    const res = await fetch(`${API}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const setCookie = res.headers.getSetCookie?.() ?? [];
    const token = setCookie.find((c) => c.startsWith('token='));
    if (token) cookie = token.split(';')[0];
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    return { status: res.status, data };
  };
  return chamar;
};

const noAr = async (url) => {
  try {
    await fetch(url, { signal: AbortSignal.timeout(4000) });
    return true;
  } catch {
    return false;
  }
};

// ---------- conta ----------
const entrar = async (api, conta) => {
  const reg = await api('POST', '/auth/register', {
    name: conta.name, email: conta.email, password: conta.password, role: conta.role, termsAccepted: true,
  });
  if (reg.status === 201 || reg.status === 200) {
    log(`Conta criada: ${conta.email}`);
  } else if (reg.status === 409) {
    log(`Conta já existia: ${conta.email} (entrando)`);
  } else {
    aviso(`Cadastro de ${conta.email} respondeu ${reg.status}: ${reg.data?.error ?? ''}`);
  }
  const login = await api('POST', '/auth/login', { email: conta.email, password: conta.password });
  if (login.status !== 200) throw new Error(`Login de ${conta.email} falhou (${login.status}): ${login.data?.error ?? ''}`);
  // aceite da versão atual dos Termos (se a conta é antiga) e o plano Premium (demonstrativo)
  await api('POST', '/auth/terms/accept', { accepted: true });
  await api('PATCH', '/auth/role', { role: conta.role });
  const plano = await api('PATCH', '/auth/plan', { plan: 'PREMIUM' });
  log(plano.status === 200 ? '  plano Premium ativo' : `  [!] troca de plano respondeu ${plano.status}`);
};

// ---------- análise de código ----------
const analisar = async (api, arquivo, rotulo) => {
  const codigo = await readFile(join(DIR, 'demo', arquivo), 'utf8');
  log(`Analisando ${rotulo} (${arquivo})... pode levar alguns minutos`);
  const r = await api('POST', '/sast/analyze', { files: { [arquivo]: codigo }, depth: 'COMPLETE' }, { timeoutMs: 6 * 60 * 1000 });
  if (r.status !== 200) {
    aviso(`  análise falhou (${r.status}): ${r.data?.error ?? ''}`);
    return null;
  }
  const achados = r.data.findings ?? [];
  log(`  ${achados.length} achado(s) em ${Number(r.data.durationSeconds ?? 0).toFixed(1)} s${r.data.historyId ? ', salvo no histórico' : ''}`);
  for (const f of achados) console.log(`     - [${f.severity}] ${f.title} (${f.affectedUrl})`);
  return r.data;
};

// ---------- varreduras ----------
const detalhe = async (api, id) => (await api('GET', `/scans/${id}`)).data?.scan ?? null;

const esperar = async (api, id, limiteMin = 15) => {
  const fim = Date.now() + limiteMin * 60 * 1000;
  let ultimo = '';
  while (Date.now() < fim) {
    const scan = await detalhe(api, id);
    if (scan && scan.status !== ultimo) {
      ultimo = scan.status;
      log(`  status: ${scan.status}`);
    }
    if (scan && FIM.has(scan.status)) return scan;
    await sleep(5000);
  }
  aviso(`  a varredura passou de ${limiteMin} min; seguindo sem esperar`);
  return detalhe(api, id);
};

const criarERodar = async (api, objective) => {
  const criada = await api('POST', '/scans', { targetUrl: LAB, objective, authorizationConfirmed: true });
  if (criada.status !== 201) {
    aviso(`  não criou a varredura ${objective} (${criada.status}): ${criada.data?.error ?? ''}`);
    return null;
  }
  const id = criada.data.scan.id;
  const run = await api('POST', `/scans/${id}/run`, {});
  if (run.status >= 300) {
    aviso(`  não iniciou a varredura ${objective} (${run.status}): ${run.data?.error ?? ''}`);
    return null;
  }
  return id;
};

const varrer = async (api, objective, rotulo) => {
  log(`Varredura "${rotulo}" (${objective}) em ${LAB}`);
  const id = await criarERodar(api, objective);
  if (!id) return null;
  const scan = await esperar(api, id);
  log(`  terminou: ${scan?.status}, ${scan?.findings?.length ?? 0} tipo(s) de achado`);
  return scan;
};

const varrerECancelar = async (api, objective, segundos) => {
  log(`Varredura completa (${objective}) que será cancelada após ~${segundos} s`);
  const id = await criarERodar(api, objective);
  if (!id) return null;
  await sleep(segundos * 1000);
  const c = await api('POST', `/scans/${id}/cancel`);
  log(`  pedido de cancelamento: ${c.status} ${c.data?.message ?? c.data?.error ?? ''}`);
  const scan = await esperar(api, id, 5);
  log(`  terminou: ${scan?.status}, ${scan?.findings?.length ?? 0} tipo(s) de achado salvos até o cancelamento`);
  return scan;
};

/** Marca alguns achados como corrigidos / falso positivo, para os gráficos de triagem. */
const triar = async (api, scan, { corrigidos = 0, falsosPositivos = 0 }) => {
  const grupos = scan?.findings ?? [];
  const idsDe = (g) => {
    const ids = (g.locations ?? []).map((l) => l.id).filter(Boolean);
    return ids.length ? ids : [g.id].filter(Boolean);
  };
  let i = 0;
  for (const [status, qtd] of [['FIXED', corrigidos], ['FALSE_POSITIVE', falsosPositivos]]) {
    for (let n = 0; n < qtd && i < grupos.length; n++, i++) {
      const r = await api('PATCH', `/scans/${scan.id}/findings/status`, { findingIds: idsDe(grupos[i]), status });
      log(`  "${grupos[i].title}" -> ${status === 'FIXED' ? 'corrigido' : 'falso positivo'} (${r.status})`);
    }
  }
};

// ---------- roteiro ----------
const main = async () => {
  console.log('== Checkop: dados de demonstração ==\n');

  if (!(await noAr(API.replace(/\/api$/, '')))) {
    throw new Error(`O backend não respondeu em ${API}. Rode o iniciar.cmd antes.`);
  }
  const motor = await noAr(`${ENGINE}/health`);
  const lab = await noAr(LAB);
  if (!motor) aviso(`Motor (${ENGINE}) fora do ar: análise de código e varreduras vão falhar.`);
  if (!lab && !SO_CODIGO) aviso(`Laboratório (${LAB}) fora do ar: as varreduras não vão achar nada.`);

  for (const conta of CONTAS) {
    console.log('');
    const api = cliente();
    await entrar(api, conta);

    if (conta.principal) {
      const c = await api('POST', '/sast/credits/purchase', { packId: 'PACK_20' });
      log(c.status === 200 ? `  ${c.data.message}` : `  [!] compra de créditos respondeu ${c.status}`);
    }

    // análise de código: a versão com falhas e a corrigida (o painel compara as duas)
    await analisar(api, 'UsuarioController.java', 'código com falhas');
    await analisar(api, 'UsuarioSeguroController.java', 'código corrigido');

    if (!conta.principal || SO_CODIGO) continue;

    // varreduras reais no laboratório (uma de cada vez: o Checkop roda uma por usuário)
    const cabecalhos = await varrer(api, 'SECURITY_HEADERS', 'Cabeçalhos de segurança');
    if (cabecalhos) await triar(api, cabecalhos, { corrigidos: 2, falsosPositivos: 1 });

    const sqli = await varrer(api, 'SQL_INJECTION', 'Injeção de SQL');
    if (sqli) await triar(api, sqli, { corrigidos: 1 });

    const arquivos = await varrer(api, 'EXPOSED_FILES', 'Arquivos sensíveis expostos');
    if (arquivos) await triar(api, arquivos, { falsosPositivos: 1 });

    // segunda SQLi no mesmo alvo: alimenta a "evolução" (a falha corrigida voltou?)
    await varrer(api, 'SQL_INJECTION', 'Injeção de SQL (reteste)');

    if (!SEM_CANCELAR) await varrerECancelar(api, 'FULL_SCAN', 45);
  }

  console.log('\nPronto. Entre em http://localhost:4200 com:');
  for (const c of CONTAS) console.log(`  ${c.email}  /  ${c.password}   (perfil ${c.role})`);
};

main().catch((error) => {
  console.error(`\n[erro] ${error.message}`);
  process.exit(1);
});
