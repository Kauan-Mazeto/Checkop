// Laboratório INTENCIONALMENTE vulnerável para validar o Checkop.
// Tem um exemplo de cada falha que o Checkop procura (ver src/constants/scan_objectives.js).
// Roda só em 127.0.0.1:3000. Não usar em rede aberta.
//
// As falhas perigosas são SIMULADAS: o lab responde do jeito que um sistema
// vulnerável responderia (um /etc/passwd falso, o resultado de uma conta...),
// mas nunca lê arquivo, nunca executa comando e nunca interpreta template de
// verdade. A única ação real é o SSRF, e só para endereços desta própria máquina.
import http from 'node:http';
import dns from 'node:dns/promises';
import os from 'node:os';

const PORT = Number(process.env.LAB_PORT ?? 3000);

// ---------- conteúdo falso devolvido nas falhas de leitura de arquivo ----------
const FAKE_PASSWD = [
  'root:x:0:0:root:/root:/bin/bash',
  'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
  'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
  'lab:x:1000:1000:Loja Lab:/home/lab:/bin/bash',
].join('\n');
const FAKE_WIN_INI = '; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n';
const FAKE_SYSTEM_INI = '; for 16-bit app support\n[386Enh]\nwoafont=dosapp.fon\n[drivers]\nwave=mmdrv.dll\ntimer=timer.drv\n';
const FAKE_WEB_XML = '<?xml version="1.0"?>\n<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">\n  <display-name>loja-lab</display-name>\n</web-app>\n';

/** Qual arquivo "sensível" o atacante pediu? Devolve o conteúdo falso equivalente. */
function fakeFileFor(value) {
  const v = value.toLowerCase().replaceAll('\\', '/');
  if (v.includes('etc/passwd')) return FAKE_PASSWD;
  if (v.includes('win.ini')) return FAKE_WIN_INI;
  if (v.includes('system.ini')) return FAKE_SYSTEM_INI;
  if (v.includes('web-inf/web.xml')) return FAKE_WEB_XML;
  return null;
}

// ---------- páginas ----------
const MAPA = [
  ['/search?q=teclado', 'Busca', 'XSS refletido'],
  ['/item?id=1', 'Produto', 'Injeção de SQL'],
  ['/ping?host=127.0.0.1', 'Teste de conexão', 'Injeção de comandos'],
  ['/index.php?page=sobre', 'Sobre a loja', 'Path Traversal / LFI'],
  ['/produtos-xml', 'Catálogo XML', 'XXE'],
  ['/saudacao?nome=cliente', 'Saudação', 'SSTI'],
  ['/idioma?lang=pt', 'Idioma', 'CRLF / injeção de cabeçalho'],
  ['/redirect?url=/item?id=2', 'Produto 2', 'Open Redirect'],
  ['/conta', 'Minha conta', 'CSRF'],
  ['/preview?url=http://127.0.0.1:3000/sobre.txt', 'Pré-visualizar link', 'SSRF'],
  ['/api/pedidos', 'API de pedidos', 'CORS mal configurado'],
  ['/uploads/', 'Uploads', 'Listagem de diretórios'],
  ['/manager/html', 'Painel Tomcat', 'Painel administrativo e login padrão'],
  ['/debug', 'Diagnóstico', 'Vazamento de informação'],
  ['/swagger-ui.html', 'Documentação da API', 'Swagger / GraphQL expostos'],
  ['/login', 'Login', 'Formulário sem proteção'],
];

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>
<h1>Loja Lab</h1>
<nav><a href="/">Início</a> | ${MAPA.map(([href, nome]) => `<a href="${href}">${nome}</a>`).join(' | ')}</nav>
${body}
<!-- TODO: remover credencial de teste admin:admin123 antes do deploy -->
</body></html>`;

const home = (q) => page('Início', `<p>Bem-vindo à Loja Lab, um site de testes com uma falha de cada tipo.</p>
${q !== null ? `<p>Você buscou: ${q}</p>` /* XSS refletido também na página inicial */ : ''}
<form action="/search"><input name="q"><button>Buscar</button></form>
<h2>Mapa das falhas</h2>
<ul>${MAPA.map(([href, nome, falha]) => `<li><a href="${href}">${nome}</a>: ${falha}</li>`).join('')}</ul>
<p>Também expostos: <a href="/.env">.env</a>, <a href="/.git/config">.git/config</a>, <a href="/index.php.bak">index.php.bak</a>,
<a href="/swagger.json">swagger.json</a> e o endpoint <code>POST /graphql</code>.</p>`);

// ---------- SSRF: só endereços desta máquina ----------
// É o bastante para o ZAP provar a falha (o "callback" dele roda neste computador)
// sem transformar o lab num proxy para a rede interna ou para a internet.
const localAddresses = () => new Set([
  '127.0.0.1', '::1',
  ...Object.values(os.networkInterfaces()).flat().filter(Boolean).map((i) => i.address),
]);

async function isLocalUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return false; }
  if (!['http:', 'https:'].includes(u.protocol)) return false;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  try {
    const addrs = await dns.lookup(host, { all: true });
    const locais = localAddresses();
    return addrs.length > 0 && addrs.every((a) => locais.has(a.address) || a.address.startsWith('127.'));
  } catch {
    return false;
  }
}

async function fetchLocal(raw) {
  if (!(await isLocalUrl(raw))) return { ok: false, text: 'Endereço fora desta máquina: o lab não acessa (limite de segurança do laboratório).' };
  try {
    const r = await fetch(raw, { redirect: 'manual', signal: AbortSignal.timeout(4000) });
    return { ok: true, text: (await r.text()).slice(0, 2000) };
  } catch (error) {
    return { ok: false, text: `Falha ao acessar: ${error.message}` };
  }
}

// ---------- servidor ----------
const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    // payload estranho de scanner nunca derruba o lab (URL impossível é normal: só responde 400)
    if (error.code !== 'ERR_INVALID_URL') console.error('requisição recusada:', error.code ?? error.message);
    if (!res.headersSent) res.writeHead(400);
    res.end();
  });
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function readBody(req, limit = 100_000) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > limit) req.destroy();
    });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(data));
  });
}

/**
 * CRLF: o lab devolve o caminho pedido no cabeçalho X-Request-Path sem limpar as
 * quebras de linha. Num servidor vulnerável isso cria cabeçalhos novos. O Node
 * não deixa escrever \r\n num cabeçalho, então o lab monta esses cabeçalhos extras.
 */
function injectedHeaders(rawUrl) {
  let decoded;
  try { decoded = decodeURIComponent(rawUrl); } catch { return {}; }
  if (!/[\r\n]/.test(decoded)) return {};
  const extra = {};
  for (const linha of decoded.split(/\r\n|\r|\n/).slice(1)) {
    const m = linha.match(/^\s*([A-Za-z0-9-]+)\s*:\s*([^&]*)/);
    if (!m || /^(content-(type|length)|transfer-encoding|connection)$/i.test(m[1])) continue;
    const value = m[2].replace(/[\u0000-\u001f\u007f-￿]/g, '').trim();
    const name = m[1];
    if (/^set-cookie$/i.test(name)) (extra['Set-Cookie'] ??= []).push(value);
    else extra[name] = value;
  }
  return extra;
}

async function handle(req, res) {
  const rawUrl = req.url ?? '/';
  // base fixa: scanners mandam Host adulterado (host header injection) e a URL
  // montada com ele ficava inválida; assim a requisição é atendida normalmente
  const url = new URL(rawUrl, 'http://lab.local');
  const param = (name) => url.searchParams.get(name);

  const baseHeaders = () => {
    const h = {
      // versões expostas (vazamento de informação / componente desatualizado)
      Server: 'Apache/2.4.49 (Unix)',
      'X-Powered-By': 'Express 4.16.0',
      // sem nenhum cabeçalho de segurança (CSP, X-Frame-Options, HSTS...): clickjacking e cabeçalhos
      ...injectedHeaders(rawUrl),
    };
    // CORS: aceita QUALQUER origem e ainda libera cookies (credenciais)
    if (req.headers.origin) {
      h['Access-Control-Allow-Origin'] = req.headers.origin;
      h['Access-Control-Allow-Credentials'] = 'true';
    }
    return h;
  };
  const send = (status, body, headers = {}, type = 'text/html; charset=utf-8') => {
    const h = { ...baseHeaders(), 'Content-Type': type, ...headers };
    const cookies = [h['Set-Cookie'], baseHeaders()['Set-Cookie']].flat().filter(Boolean);
    if (cookies.length) h['Set-Cookie'] = [...new Set(cookies)];
    res.writeHead(status, h);
    res.end(body);
  };
  const text = (status, body, headers) => send(status, body, headers, 'text/plain; charset=utf-8');
  const json = (status, obj, headers) => send(status, JSON.stringify(obj, null, 2), headers, 'application/json');

  // ---- CVE-2021-41773 (Apache 2.4.49): path traversal com ".%2e" ----
  // olha a URL CRUA: o parser normaliza o ".%2e" e o ataque sumiria antes de chegar aqui
  if (/^\/(icons|cgi-bin)\//i.test(rawUrl) && /%2e/i.test(rawUrl)) {
    const conteudo = fakeFileFor(decodeURIComponent(rawUrl.replace(/%(?![0-9a-f]{2})/gi, '%25')));
    if (conteudo) return text(200, conteudo);
  }

  switch (url.pathname) {
    case '/':
      // cookie de sessão sem HttpOnly, Secure nem SameSite
      return send(200, home(param('q')), { 'Set-Cookie': 'sessionid=abc123; Path=/' });

    case '/search':
      // XSS refletido: o parâmetro volta na página sem escape
      return send(200, page('Busca', `<p>Resultados para: ${param('q') ?? ''}</p>`));

    case '/item': {
      // Injeção de SQL: aspas no parâmetro geram erro de banco exposto
      const id = param('id') ?? '';
      if (/['"]/.test(id)) {
        return send(500, page('Erro', `<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${id}' at line 1</pre>`));
      }
      return send(200, page('Produto', `<p>Produto ${Number(id) || 1}</p>`));
    }

    case '/ping': {
      // Injeção de comandos: "roda" ping <host> no shell. Simulado: nada é executado.
      const host = param('host') ?? '127.0.0.1';
      let saida = `PING ${host} 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.04 ms\n\n1 packets transmitted, 1 received, 0% packet loss`;
      if (/\(\)\s*\{/.test(host)) {
        // "() { :;}; ..." (teste de Shell Shock) quebra a sintaxe do sh: num servidor real
        // nada roda. Sem isso o lab "dormia" e o ZAP classificava como Shell Shock.
        saida = `sh: 1: Syntax error: "(" unexpected`;
      } else if (/[;|&`\n]|\$\(/.test(host)) {
        // o que viria depois do separador teria rodado no servidor
        const espera = host.match(/(?:\bsleep|timeout\s+\/t|start-sleep\s+-s(?:econds)?)\s+(\d+)/i);
        if (espera) await sleep(Math.min(Number(espera[1]), 15) * 1000);
        const arquivo = fakeFileFor(host);
        if (arquivo) saida += `\n${arquivo}`;
        if (/\bid\b|whoami/i.test(host)) saida += '\nuid=33(www-data) gid=33(www-data) groups=33(www-data)';
      }
      return send(200, page('Teste de conexão', `<form action="/ping"><input name="host" value="${escapeHtml(host)}"><button>Testar</button></form><pre>${saida}</pre>`));
    }

    case '/index.php': {
      // Path Traversal / LFI: include($_GET['page']). Simulado: devolve arquivos falsos.
      const pagina = param('page') ?? 'sobre';
      const arquivo = fakeFileFor(pagina);
      if (arquivo) return send(200, page('Sobre', `<pre>${arquivo}</pre>`));
      if (pagina === 'sobre') return send(200, page('Sobre', '<p>A Loja Lab existe desde 2026.</p>'));
      return send(200, page('Sobre', `<p>Warning: include(${escapeHtml(pagina)}.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 7</p>`));
    }

    case '/index.php.bak':
      // backup do código-fonte esquecido no servidor
      return text(200, '<?php\n// conexão do banco (senha FALSA do lab)\n$db = new mysqli("localhost", "root", "senha-falsa-do-lab", "loja");\ninclude($_GET["page"] . ".php");\n');

    case '/produtos-xml':
      // a página chama a API em XML ao abrir (o Ajax Spider do ZAP registra essa chamada)
      return send(200, page('Catálogo XML', `<p>Catálogo carregado da API em XML:</p><pre id="r">carregando...</pre>
<script>
fetch('/api/produtos', { method: 'POST', headers: { 'Content-Type': 'application/xml' },
  body: '<?xml version="1.0"?><busca><nome>teclado</nome></busca>' })
  .then((r) => r.text()).then((t) => { document.getElementById('r').textContent = t; });
</script>`));

    case '/api/produtos': {
      // XXE: o parser XML resolve entidades externas. Simulado: só os arquivos falsos
      // e, para entidade http, o mesmo acesso restrito à máquina do SSRF.
      if (req.method !== 'POST') return json(405, { erro: 'use POST com XML' });
      const corpo = await readBody(req);
      let resultado = corpo.match(/<nome>([\s\S]*?)<\/nome>/)?.[1] ?? 'teclado';
      for (const [, nome, sistema] of corpo.matchAll(/<!ENTITY\s+(?:%\s*)?(\w+)\s+SYSTEM\s+["']([^"']+)["']/gi)) {
        const valor = fakeFileFor(sistema) ?? (/^https?:/i.test(sistema) ? (await fetchLocal(sistema)).text : '');
        resultado = resultado.replaceAll(`&${nome};`, valor);
      }
      return send(200, `<?xml version="1.0"?><resultado><busca>${resultado}</busca><total>0</total></resultado>`, {}, 'application/xml');
    }

    case '/saudacao': {
      // SSTI: o nome vira parte do template. Simulado: só resolve contas de multiplicação
      // ({{7*7}}, ${7*7}, <%= 7*7 %>...), que é o que os scanners usam para provar a falha.
      const nome = param('nome') ?? 'cliente';
      const renderizado = nome.replace(
        /(\{\{=?|\$\{|#\{|\*\{|<%=?|\[=|@\(|\{)\s*(-?\d{1,12})\s*\*\s*(-?\d{1,12})\s*(\}\}|\}|%>|\]|\))/g,
        (_, _a, x, y) => String(BigInt(x) * BigInt(y)),
      );
      return send(200, page('Saudação', `<p>Olá, ${renderizado}!</p>`));
    }

    case '/idioma':
      // CRLF: o idioma vai para um cookie sem limpar quebras de linha (ver injectedHeaders)
      return send(200, page('Idioma', `<p>Idioma escolhido: ${escapeHtml(param('lang') ?? 'pt')}</p>`), {
        'Set-Cookie': `lang=${(param('lang') ?? 'pt').replace(/[\r\n].*/s, '').replace(/[^\w-]/g, '')}; Path=/`,
      });

    case '/redirect': {
      // Open Redirect: aceita qualquer destino
      const location = param('url') ?? '/';
      // o teste de CRLF do ZAP manda \r\n aqui; o Node recusa e o lab caía
      if (/[\r\n\u0000-\u001f\u007f-￿]/.test(location)) return send(400, page('Erro', '<p>Destino inválido.</p>'));
      return send(302, '', { Location: location });
    }

    case '/conta':
      // CSRF: formulário que altera dados sem token anti-CSRF
      return send(200, page('Minha conta', `<form method="post" action="/conta/email">
<label>Novo e-mail <input name="email" type="email"></label><button>Alterar e-mail</button></form>`));

    case '/conta/email': {
      const email = new URLSearchParams(await readBody(req)).get('email') ?? '';
      return send(200, page('Minha conta', `<p>E-mail alterado para ${escapeHtml(email)}.</p>`));
    }

    case '/login':
      if (req.method === 'POST') await readBody(req);
      return send(200, page('Login', '<form method="post" action="/login"><input name="user"><input type="password" name="pass"><button>Entrar</button></form>'));

    case '/preview': {
      // SSRF: o servidor busca a URL informada (só endereços desta máquina, ver fetchLocal)
      const alvo = param('url') ?? '';
      const r = alvo ? await fetchLocal(alvo) : { text: '' };
      return send(200, page('Pré-visualizar link', `<form action="/preview"><input name="url" value="${escapeHtml(alvo)}"><button>Ver</button></form><pre>${escapeHtml(r.text)}</pre>`));
    }

    case '/sobre.txt':
      return text(200, 'Loja Lab: página interna usada pelo exemplo de SSRF.');

    case '/api/pedidos':
      // CORS mal configurado (ver baseHeaders): qualquer site lê estes dados com o cookie da vítima
      return json(200, { pedidos: [{ id: 1, cliente: 'Maria (dado FALSO)', total: 199.9 }] });

    case '/uploads':
    case '/uploads/':
      // Listagem de diretórios, no formato do Apache
      return send(200, `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>
<table><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>
<tr><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td>-</td></tr>
<tr><td><a href="relatorio-vendas.xlsx">relatorio-vendas.xlsx</a></td><td>2026-11-20 10:02</td><td>48K</td></tr>
<tr><td><a href="backup-clientes.csv">backup-clientes.csv</a></td><td>2026-11-21 23:40</td><td>1.2M</td></tr>
</table><address>Apache/2.4.49 (Unix) Server at localhost Port ${PORT}</address></body></html>`);

    case '/manager/html':
    case '/manager/status': {
      // Painel do Tomcat exposto, com o login padrão tomcat:tomcat
      const auth = req.headers.authorization ?? '';
      const [user, pass] = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString().split(':');
      if (user === 'tomcat' && pass === 'tomcat') {
        return send(200, `<html><head><title>/manager</title></head><body><h1>Tomcat Web Application Manager</h1>
<h2>Server Information</h2><table><tr><th>Tomcat Version</th><th>JVM Version</th><th>JVM Vendor</th><th>OS Name</th></tr>
<tr><td>Apache Tomcat/9.0.30</td><td>11.0.6+10</td><td>Oracle Corporation</td><td>Linux</td></tr></table>
<p>Apache Tomcat</p></body></html>`);
      }
      return send(401, '<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1><p>Apache Tomcat/9.0.30 - you are not authorized to view this page. See conf/tomcat-users.xml</p></body></html>', {
        'WWW-Authenticate': 'Basic realm="Tomcat Manager Application"',
      });
    }

    case '/debug':
      // Vazamento de informação: stack trace completo com caminhos internos
      return send(500, page('Erro interno', `<h2>Internal Server Error</h2><pre>java.lang.NullPointerException: Cannot invoke "String.length()" because "nome" is null
\tat com.lojalab.web.CarrinhoController.calcular(CarrinhoController.java:42)
\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
\tat org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:202)
DB_URL=jdbc:mysql://10.0.0.12:3306/loja (usuário root)</pre>`));

    case '/swagger-ui.html':
      return send(200, `<!doctype html><html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div>
<script>window.onload = () => loadSwaggerUI({ url: '/swagger.json' });</script></body></html>`);

    case '/swagger.json':
    case '/v2/api-docs':
      return json(200, {
        swagger: '2.0',
        info: { title: 'Loja Lab API (interna)', version: '1.0' },
        paths: { '/api/pedidos': { get: { summary: 'Lista todos os pedidos' } }, '/api/admin/usuarios': { delete: { summary: 'Apaga usuário' } } },
      });

    case '/graphql': {
      // GraphQL com introspecção ligada
      if (req.method === 'POST') await readBody(req);
      return json(200, { data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'Pedido' }, { name: 'Usuario' }] } } });
    }

    case '/.env':
      // arquivo de configuração exposto (segredos FALSOS)
      return text(200, 'DB_HOST=localhost\nDB_USER=root\nDB_PASSWORD=senha-falsa-do-lab\nAPP_KEY=base64:ZmFrZS1rZXktZG8tbGFiLWNoZWNrb3A=\n');

    case '/.git/config':
      return text(200, '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/exemplo/loja-lab.git\n');

    case '/.git/HEAD':
      return text(200, 'ref: refs/heads/main\n');

    default:
      return send(404, page('404', `<p>Página ${escapeHtml(url.pathname)} não encontrada</p>`));
  }
}

// LAB_HOST=0.0.0.0 só dentro do Docker (a porta é publicada apenas em 127.0.0.1 do computador)
const HOST = process.env.LAB_HOST ?? '127.0.0.1';
server.listen(PORT, HOST, () => console.log(`lab vulnerável em http://${HOST}:${PORT}`));
