# 12 — Laboratório com um exemplo de cada falha

**Data:** 2026-11-26 · **Status:** Implementado; validação com Nuclei/ZAP pendente · **Requisitos:** RF-29 a RF-39

## 1. Problema
O laboratório vulnerável (`backend/lab/lab-vulneravel.mjs`) cobria só umas 8 das categorias que o Checkop procura (XSS, SQLi, open redirect, cookies, cabeçalhos, clickjacking, `.env`/`.git`, vazamento de informação). Para demonstrar e validar o Checkop, faltava um alvo com **um exemplo de cada objetivo** de `src/constants/scan_objectives.js`.

## 2. Proposta
Uma rota por falha. A página inicial vira um mapa com links para todas, para o spider achar tudo. Cada resposta segue o que o detector real espera: o matcher do template do Nuclei e a regra do ZAP.

Fora do escopo, porque não dá para reproduzir num alvo local por HTTP: **TLS/SSL**, **DNS/subdomain takeover** e **enumeração de subdomínios**.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Falha real ou simulada | Executar de verdade; simular a resposta | **Simular**. O lab devolve um `/etc/passwd` falso, calcula só contas de multiplicação no SSTI e não executa comando nenhum. Dá o mesmo sinal para o scanner sem risco para a máquina. |
| SSRF | Bloquear tudo; acesso livre; só esta máquina | **Só endereços desta máquina** (loopback e interfaces locais). O callback do ZAP roda no mesmo computador, então a prova funciona, mas o lab não vira proxy para a rede interna. |
| CRLF | Rota única; todas as rotas | **Todas**: o lab "ecoa" a URL num cabeçalho, como servidores mal configurados fazem. Assim pega tanto o ZAP (parâmetros) quanto o template genérico do Nuclei (caminho). O Node não aceita `\r\n` em cabeçalho, então o lab monta os cabeçalhos injetados. |
| CVE conhecido | Inventar; emular um CVE real | **CVE-2021-41773 (Apache 2.4.49)**, com `Server: Apache/2.4.49`. O template oficial do Nuclei bate na resposta. A URL é lida crua, porque o parser normaliza `.%2e` e o ataque sumiria. |

## 4. O que foi implementado
`backend/lab/lab-vulneravel.mjs`, reescrito:

| Objetivo | Rota | Como responde |
|---|---|---|
| XSS | `/search?q=`, `/?q=` | reflete sem escape |
| SQLi | `/item?id=` | erro MySQL com aspas |
| Injeção de comandos | `/ping?host=` | após `;` `\|` `&`: passwd/win.ini falsos, `id`, e espera em `sleep N` (máx. 15 s) |
| Path Traversal / LFI | `/index.php?page=` | passwd, win.ini, system.ini, web.xml falsos |
| XXE | `/produtos-xml` → `POST /api/produtos` | resolve `<!ENTITY … SYSTEM>` (arquivo falso ou URL local) |
| SSTI | `/saudacao?nome=` | `{{a*b}}`, `${a*b}`, `<%= a*b %>`… viram o produto |
| CRLF | `/idioma?lang=` e qualquer rota | cabeçalhos injetados aparecem na resposta |
| Open Redirect | `/redirect?url=` | `Location` com qualquer destino |
| CSRF | `/conta` | formulário POST sem token |
| SSRF | `/preview?url=` | busca a URL (só esta máquina) |
| CORS | todas, ex.: `/api/pedidos` | reflete `Origin` + `Allow-Credentials: true` |
| Listagem de diretórios | `/uploads/` | "Index of /uploads" do Apache |
| Painel admin e login padrão | `/manager/html` | Tomcat: 401 sem login, 200 com `tomcat:tomcat` |
| Vazamento de informação | `/debug`, cabeçalhos, comentário HTML | stack trace, `Server`/`X-Powered-By` |
| Swagger / GraphQL | `/swagger-ui.html`, `/swagger.json`, `/v2/api-docs`, `POST /graphql` | documentação e introspecção abertas |
| Arquivos expostos | `/.env`, `/.git/config`, `/.git/HEAD`, `/index.php.bak` | segredos falsos |
| CVE conhecido | `/icons/.%2e/…/etc/passwd` | CVE-2021-41773 |
| Cabeçalhos, cookies, clickjacking | todas | sem CSP/HSTS/XFO; cookie sem HttpOnly/Secure/SameSite |

## 5. Como foi validado
- Lab subido na porta 3999 e 33 verificações com `curl`, uma por falha, incluindo os limites de segurança (SSRF para `example.com` recusado, Tomcat com senha errada → 401): **todas OK**.
- **Pendente:** rodar o Nuclei e o ZAP (varredura completa pelo Checkop) contra o lab e confirmar que cada objetivo gera o achado esperado. O XXE depende do Ajax Spider do ZAP registrar a chamada XML que a página `/produtos-xml` faz ao abrir.

## 6. Limitações e riscos conhecidos
- TLS/SSL, DNS e subdomínios não têm exemplo (precisam de HTTPS e domínio real).
- O lab continua para uso só local (`127.0.0.1`); no Docker a porta é publicada apenas em `127.0.0.1`.
- Algumas regras do ZAP usam OAST (callback). Se o callback do ZAP não estiver acessível, SSRF e XXE "cegos" podem não aparecer.

## 7. Para os slides
- O Checkop tem um alvo próprio com **um exemplo de cada falha** que ele procura.
- As falhas são simuladas: o alvo "parece" vulnerável para o scanner, mas não executa nada de verdade.
- Serve para a demonstração ao vivo na banca e para medir se cada detector funciona.
