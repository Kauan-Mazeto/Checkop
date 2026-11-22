// Laboratório INTENCIONALMENTE vulnerável para validar o Checkop.
// Roda só em 127.0.0.1:3000. Não usar em rede aberta.
import http from 'node:http';

const PORT = Number(process.env.LAB_PORT ?? 3000);

const page = (title, body) => `<!doctype html><html><head><title>${title}</title></head><body>
<h1>Loja Lab</h1>
<nav><a href="/">Início</a> | <a href="/search?q=teclado">Busca</a> | <a href="/item?id=1">Produto 1</a> |
<a href="/redirect?url=/item?id=2">Produto 2</a> | <a href="/login">Login</a></nav>
${body}
<!-- TODO: remover credencial de teste admin:admin123 antes do deploy -->
</body></html>`;

const server = http.createServer((req, res) => {
  try {
    handle(req, res);
  } catch (error) {
    // payload estranho de scanner nunca derruba o lab (URL impossível é normal: só responde 400)
    if (error.code !== 'ERR_INVALID_URL') console.error('requisição recusada:', error.code ?? error.message);
    if (!res.headersSent) res.writeHead(400);
    res.end();
  }
});

function handle(req, res) {
  // base fixa: scanners mandam Host adulterado (host header injection) e a URL
  // montada com ele ficava inválida; assim a requisição é atendida normalmente
  const url = new URL(req.url, 'http://lab.local');
  const send = (status, html, headers = {}) => {
    // sem nenhum cabeçalho de segurança (CSP, X-Frame-Options, HSTS...)
    res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'X-Powered-By': 'Express 4.16.0', ...headers });
    res.end(html);
  };

  switch (url.pathname) {
    case '/':
      // cookie de sessão sem HttpOnly, Secure nem SameSite
      return send(200, page('Início', '<p>Bem-vindo.</p><form action="/search"><input name="q"><button>Buscar</button></form>'), {
        'Set-Cookie': 'sessionid=abc123; Path=/',
      });

    case '/search':
      // XSS refletido: o parâmetro volta na página sem escape
      return send(200, page('Busca', `<p>Resultados para: ${url.searchParams.get('q') ?? ''}</p>`));

    case '/item': {
      // "SQL Injection": aspas no parâmetro geram erro de banco exposto
      const id = url.searchParams.get('id') ?? '';
      if (/['"]/.test(id)) {
        return send(500, page('Erro', `<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${id}' at line 1</pre>`));
      }
      return send(200, page('Produto', `<p>Produto ${Number(id) || 1}</p>`));
    }

    case '/redirect': {
      // redirecionamento aberto: aceita qualquer destino
      const location = url.searchParams.get('url') ?? '/';
      // o teste de CRLF do ZAP manda \r\n aqui; o Node recusa e o lab caía
      if (/[\r\n\u0000-\u001f\u007f-￿]/.test(location)) return send(400, page('Erro', '<p>Destino inválido.</p>'));
      res.writeHead(302, { Location: location });
      return res.end();
    }

    case '/login':
      return send(200, page('Login', '<form method="post" action="/login"><input name="user"><input type="password" name="pass"><button>Entrar</button></form>'));

    case '/.env':
      // arquivo de configuração exposto (segredos FALSOS)
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('DB_HOST=localhost\nDB_USER=root\nDB_PASSWORD=senha-falsa-do-lab\nAPP_KEY=base64:ZmFrZS1rZXktZG8tbGFiLWNoZWNrb3A=\n');

    case '/.git/config':
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/exemplo/loja-lab.git\n');

    default:
      return send(404, page('404', `<p>Página ${url.pathname} não encontrada</p>`));
  }
}

// LAB_HOST=0.0.0.0 só dentro do Docker (a porta é publicada apenas em 127.0.0.1 do computador)
const HOST = process.env.LAB_HOST ?? '127.0.0.1';
server.listen(PORT, HOST, () => console.log(`lab vulnerável em http://${HOST}:${PORT}`));
