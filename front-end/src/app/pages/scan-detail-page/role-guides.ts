// Conteúdo de cada perfil no detalhe do achado (RF-11):
//   Estudante: o que é, por que é perigoso e onde estudar / como corrigir
//   QA:        entender a falha, padrões que comprovam e o texto do ticket
//   Pentester: material de exploração e o vetor CVSS explicado
// Por CLASSE de falha (SQLi, XSS, cabeçalho...), reconhecida pelo título, OWASP e regra:
// vale para qualquer ferramenta. Links só de fontes oficiais e estáveis.

import { Finding } from '../../core/services/scan.service';

export interface GuideLink {
  label: string;
  url: string;
}

export interface FlawGuide {
  /** nome da classe em português */
  name: string;
  cwe: number | null;
  /** o que é, em linguagem simples */
  what: string;
  /** o que um atacante consegue */
  impact: string;
  /** QA: como conferir que a falha existe (e que sumiu depois da correção) */
  verify: string;
  /** QA: comportamento esperado do sistema correto */
  expected: string;
  /** QA: critério de aceite do ticket */
  acceptance: string;
  /** Estudante: onde estudar e como corrigir */
  learn: GuideLink[];
  /** Pentester: material de exploração da classe */
  attack: GuideLink[];
}

const OWASP_TOP10: Record<string, GuideLink> = {
  A01: { label: 'OWASP Top 10 · A01 Controle de acesso quebrado', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A02: { label: 'OWASP Top 10 · A02 Falhas de criptografia', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  A03: { label: 'OWASP Top 10 · A03 Injeção', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  A04: { label: 'OWASP Top 10 · A04 Design inseguro', url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  A05: { label: 'OWASP Top 10 · A05 Configuração incorreta', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A06: { label: 'OWASP Top 10 · A06 Componentes vulneráveis', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  A07: { label: 'OWASP Top 10 · A07 Falhas de autenticação', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
  A08: { label: 'OWASP Top 10 · A08 Integridade de software e dados', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  A09: { label: 'OWASP Top 10 · A09 Falhas de log e monitoramento', url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  A10: { label: 'OWASP Top 10 · A10 SSRF', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' },
};

const CHEAT = 'https://cheatsheetseries.owasp.org/cheatsheets/';
const PORTSWIGGER = 'https://portswigger.net/web-security/';
const PATT = 'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/';
const MDN = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/';

interface ClassRule {
  match: RegExp;
  guide: FlawGuide;
}

const CLASSES: ClassRule[] = [
  {
    match: /sql[\s-]*inj|sqli\b|injeção de sql/i,
    guide: {
      name: 'Injeção de SQL', cwe: 89,
      what: 'O texto que o usuário envia entra direto na consulta ao banco. Com aspas e comandos SQL, ele muda o que a consulta faz.',
      impact: 'Ler ou apagar dados de outros usuários, entrar sem senha e, em alguns bancos, executar comandos no servidor.',
      verify: 'Envie no parâmetro um apóstrofo (\') ou o payload usado na evidência e observe erro de banco, resposta diferente ou atraso.',
      expected: 'A entrada é tratada como dado: a página responde igual (ou com erro de validação) e nenhuma mensagem do banco aparece.',
      acceptance: 'O payload da evidência não altera a resposta; a consulta usa parâmetros (prepared statements) e o teste automático passa.',
      learn: [
        { label: 'PortSwigger Academy · SQL injection (explicação + laboratórios)', url: `${PORTSWIGGER}sql-injection` },
        { label: 'OWASP Cheat Sheet · Prevenção de SQL Injection', url: `${CHEAT}SQL_Injection_Prevention_Cheat_Sheet.html` },
        { label: 'OWASP Cheat Sheet · Consultas parametrizadas', url: `${CHEAT}Query_Parameterization_Cheat_Sheet.html` },
      ],
      attack: [
        { label: 'PayloadsAllTheThings · SQL Injection', url: `${PATT}SQL%20Injection` },
        { label: 'PortSwigger · SQL injection cheat sheet', url: `${PORTSWIGGER}sql-injection/cheat-sheet` },
      ],
    },
  },
  {
    match: /xss|cross[\s-]*site[\s-]*scripting/i,
    guide: {
      name: 'Cross-Site Scripting (XSS)', cwe: 79,
      what: 'A página mostra o que o usuário enviou sem escapar o HTML. Um <script> enviado vira código rodando no navegador de quem abre a página.',
      impact: 'Roubar a sessão (cookie), agir como a vítima, trocar o conteúdo da página e capturar o que ela digita.',
      verify: 'Envie no parâmetro o payload da evidência (ou <script>alert(1)</script>) e veja se ele volta na página sem escape.',
      expected: 'O texto aparece escapado (&lt;script&gt;) e nada é executado.',
      acceptance: 'A saída é escapada no contexto (HTML, atributo, JS); o payload da evidência aparece como texto e uma CSP restringe scripts.',
      learn: [
        { label: 'PortSwigger Academy · Cross-site scripting', url: `${PORTSWIGGER}cross-site-scripting` },
        { label: 'OWASP Cheat Sheet · Prevenção de XSS', url: `${CHEAT}Cross_Site_Scripting_Prevention_Cheat_Sheet.html` },
      ],
      attack: [
        { label: 'PayloadsAllTheThings · XSS Injection', url: `${PATT}XSS%20Injection` },
        { label: 'PortSwigger · XSS cheat sheet', url: 'https://portswigger.net/web-security/cross-site-scripting/cheat-sheet' },
      ],
    },
  },
  {
    match: /csrf|cross[\s-]*site[\s-]*request|anti-csrf/i,
    guide: {
      name: 'Falsificação de requisição (CSRF)', cwe: 352,
      what: 'O formulário não tem um token próprio da sessão. Outro site consegue fazer o navegador da vítima enviar o formulário por ela.',
      impact: 'Trocar senha ou e-mail, fazer compras ou transferências em nome de quem está logado.',
      verify: 'Envie o formulário a partir de outra origem (ou sem o token) e veja se o servidor aceita.',
      expected: 'Requisições sem token válido (ou de outra origem) são recusadas.',
      acceptance: 'Todo formulário que muda estado exige token anti-CSRF; o cookie de sessão usa SameSite=Lax ou Strict.',
      learn: [
        { label: 'PortSwigger Academy · CSRF', url: `${PORTSWIGGER}csrf` },
        { label: 'OWASP Cheat Sheet · Prevenção de CSRF', url: `${CHEAT}Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html` },
      ],
      attack: [{ label: 'PayloadsAllTheThings · CSRF', url: `${PATT}Cross-Site%20Request%20Forgery` }],
    },
  },
  {
    match: /ssrf|server[\s-]*side[\s-]*request/i,
    guide: {
      name: 'SSRF', cwe: 918,
      what: 'O servidor busca uma URL que o usuário escolhe. O atacante aponta para endereços internos que só o servidor alcança.',
      impact: 'Ler serviços internos, metadados da nuvem (credenciais) e atacar outras máquinas da rede.',
      verify: 'Troque a URL do parâmetro por um endereço interno (127.0.0.1, 169.254.169.254) e veja se o servidor responde com o conteúdo.',
      expected: 'Endereços internos e esquemas não permitidos são recusados.',
      acceptance: 'Só destinos de uma lista permitida são aceitos; IPs internos e redirecionamentos para eles são bloqueados.',
      learn: [
        { label: 'PortSwigger Academy · SSRF', url: `${PORTSWIGGER}ssrf` },
        { label: 'OWASP Cheat Sheet · Prevenção de SSRF', url: `${CHEAT}Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html` },
      ],
      attack: [{ label: 'PayloadsAllTheThings · SSRF', url: `${PATT}Server%20Side%20Request%20Forgery` }],
    },
  },
  {
    match: /redirect|redirecionamento/i,
    guide: {
      name: 'Redirecionamento aberto', cwe: 601,
      what: 'A aplicação redireciona para qualquer endereço recebido no parâmetro, inclusive sites de terceiros.',
      impact: 'Phishing com um link que começa no seu domínio confiável e leva a um site falso.',
      verify: 'Troque o destino do parâmetro por um site externo e veja se o navegador é levado até ele.',
      expected: 'Destinos fora do próprio site são recusados ou trocados pela página inicial.',
      acceptance: 'Só caminhos internos ou uma lista permitida de destinos são aceitos.',
      learn: [{ label: 'OWASP Cheat Sheet · Redirecionamentos não validados', url: `${CHEAT}Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html` }],
      attack: [{ label: 'PayloadsAllTheThings · Open Redirect', url: `${PATT}Open%20Redirect` }],
    },
  },
  {
    match: /path[\s-]*traversal|directory[\s-]*traversal|\blfi\b|local file|inclusão de arquivo/i,
    guide: {
      name: 'Path traversal / inclusão de arquivo', cwe: 22,
      what: 'O nome de arquivo vem do usuário. Com ../ ele sai da pasta permitida e lê qualquer arquivo do servidor.',
      impact: 'Ler senhas, chaves e código-fonte do servidor.',
      verify: 'Envie ../../etc/passwd (ou o payload da evidência) no parâmetro e veja se o conteúdo do arquivo aparece.',
      expected: 'Caminhos com ../ ou absolutos são recusados.',
      acceptance: 'O arquivo é escolhido por um identificador de uma lista permitida; o caminho final é conferido dentro da pasta base.',
      learn: [
        { label: 'PortSwigger Academy · Path traversal', url: `${PORTSWIGGER}file-path-traversal` },
        { label: 'OWASP · Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
      ],
      attack: [{ label: 'PayloadsAllTheThings · Directory Traversal', url: `${PATT}Directory%20Traversal` }],
    },
  },
  {
    match: /command[\s-]*inj|injeção de comando|remote[\s-]*code|\brce\b|os command/i,
    guide: {
      name: 'Injeção de comandos', cwe: 78,
      what: 'O que o usuário envia vira parte de um comando do sistema operacional.',
      impact: 'Executar qualquer comando no servidor: assumir a máquina, ler e apagar tudo.',
      verify: 'Envie o payload da evidência (ex.: ; sleep 5) e veja se a resposta atrasa ou traz a saída do comando.',
      expected: 'A entrada nunca chega ao shell; caracteres especiais não mudam o comportamento.',
      acceptance: 'O comando usa API sem shell (lista de argumentos) e a entrada é validada contra uma lista permitida.',
      learn: [
        { label: 'PortSwigger Academy · OS command injection', url: `${PORTSWIGGER}os-command-injection` },
        { label: 'OWASP Cheat Sheet · Defesa contra injeção de comandos', url: `${CHEAT}OS_Command_Injection_Defense_Cheat_Sheet.html` },
      ],
      attack: [{ label: 'PayloadsAllTheThings · Command Injection', url: `${PATT}Command%20Injection` }],
    },
  },
  {
    match: /template[\s-]*inj|ssti/i,
    guide: {
      name: 'Injeção de template (SSTI)', cwe: 1336,
      what: 'O texto do usuário vira parte do template, e o motor de templates executa o que estiver nele.',
      impact: 'Normalmente leva a execução de código no servidor.',
      verify: 'Envie {{7*7}} no parâmetro e veja se a página mostra 49.',
      expected: 'O texto aparece literalmente, sem ser calculado.',
      acceptance: 'O template é fixo e os valores entram como variáveis; o payload {{7*7}} aparece como texto.',
      learn: [
        { label: 'PortSwigger Academy · Server-side template injection', url: `${PORTSWIGGER}server-side-template-injection` },
        { label: 'OWASP WSTG · Testar SSTI', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection' },
      ],
      attack: [{ label: 'PayloadsAllTheThings · SSTI', url: `${PATT}Server%20Side%20Template%20Injection` }],
    },
  },
  {
    match: /xxe|xml external/i,
    guide: {
      name: 'XXE (entidade externa em XML)', cwe: 611,
      what: 'O leitor de XML aceita entidades externas, que fazem o servidor abrir arquivos ou URLs indicados no XML.',
      impact: 'Ler arquivos do servidor e fazer requisições internas (SSRF).',
      verify: 'Envie um XML com <!ENTITY x SYSTEM "file:///etc/passwd"> e veja se o conteúdo volta.',
      expected: 'DTDs e entidades externas são recusadas.',
      acceptance: 'O parser XML tem DTD e entidades externas desligadas.',
      learn: [
        { label: 'PortSwigger Academy · XXE', url: `${PORTSWIGGER}xxe` },
        { label: 'OWASP Cheat Sheet · Prevenção de XXE', url: `${CHEAT}XML_External_Entity_Prevention_Cheat_Sheet.html` },
      ],
      attack: [{ label: 'PayloadsAllTheThings · XXE Injection', url: `${PATT}XXE%20Injection` }],
    },
  },
  {
    match: /clickjacking|anti-clickjacking|x-frame-options|frame-ancestors/i,
    guide: {
      name: 'Clickjacking', cwe: 1021,
      what: 'A página pode ser aberta dentro de um iframe de outro site, escondida embaixo de botões falsos.',
      impact: 'Fazer a vítima clicar sem saber em ações da sua aplicação (confirmar, excluir, transferir).',
      verify: 'Abra a página dentro de um <iframe> num arquivo HTML local e veja se ela carrega.',
      expected: 'A página se recusa a carregar dentro de iframe de outra origem.',
      acceptance: 'Todas as páginas enviam X-Frame-Options: DENY (ou CSP frame-ancestors \'none\').',
      learn: [
        { label: 'PortSwigger Academy · Clickjacking', url: `${PORTSWIGGER}clickjacking` },
        { label: 'OWASP Cheat Sheet · Defesa contra clickjacking', url: `${CHEAT}Clickjacking_Defense_Cheat_Sheet.html` },
        { label: 'MDN · X-Frame-Options', url: `${MDN}X-Frame-Options` },
      ],
      attack: [{ label: 'PortSwigger · Clickjacking', url: `${PORTSWIGGER}clickjacking` }],
    },
  },
  {
    match: /content[\s-]*security[\s-]*policy|\bcsp\b/i,
    guide: {
      name: 'Content-Security-Policy ausente', cwe: 693,
      what: 'Sem CSP, o navegador executa qualquer script que aparecer na página, de qualquer origem.',
      impact: 'Um XSS em qualquer lugar do site fica muito mais fácil de explorar.',
      verify: 'Veja nos cabeçalhos da resposta se existe Content-Security-Policy (DevTools > Rede).',
      expected: 'Toda página HTML envia uma CSP que limita scripts às origens confiáveis.',
      acceptance: 'O cabeçalho Content-Security-Policy está presente em todas as páginas, sem unsafe-inline nos scripts.',
      learn: [
        { label: 'OWASP Cheat Sheet · Content Security Policy', url: `${CHEAT}Content_Security_Policy_Cheat_Sheet.html` },
        { label: 'MDN · Content-Security-Policy', url: `${MDN}Content-Security-Policy` },
      ],
      attack: [{ label: 'PortSwigger · Contornar CSP', url: `${PORTSWIGGER}cross-site-scripting/content-security-policy` }],
    },
  },
  {
    match: /cookie|httponly|samesite|secure flag/i,
    guide: {
      name: 'Cookie sem proteção', cwe: 1004,
      what: 'O cookie (normalmente o de sessão) foi criado sem os atributos que o protegem: HttpOnly, Secure e SameSite.',
      impact: 'Sem HttpOnly, um XSS rouba a sessão; sem Secure, ela vaza em HTTP; sem SameSite, facilita CSRF.',
      verify: 'Veja o cabeçalho Set-Cookie na resposta (DevTools > Aplicativo > Cookies) e confira os atributos.',
      expected: 'O cookie de sessão tem HttpOnly, Secure e SameSite=Lax (ou Strict).',
      acceptance: 'Set-Cookie do cookie de sessão traz HttpOnly; Secure; SameSite=Lax.',
      learn: [
        { label: 'OWASP Cheat Sheet · Gerenciamento de sessão', url: `${CHEAT}Session_Management_Cheat_Sheet.html` },
        { label: 'MDN · Set-Cookie', url: `${MDN}Set-Cookie` },
      ],
      attack: [{ label: 'PortSwigger · Cookies e SameSite', url: `${PORTSWIGGER}csrf/bypassing-samesite-restrictions` }],
    },
  },
  {
    match: /na url|in url|query string|sensitive information in url|informações confidenciais na url/i,
    guide: {
      name: 'Dado sensível na URL', cwe: 598,
      what: 'Senha, token ou dado pessoal vai na própria URL (?senha=...).',
      impact: 'A URL fica no histórico, em logs de servidor e proxy e no cabeçalho Referer enviado a outros sites.',
      verify: 'Veja a URL das requisições (DevTools > Rede) e procure senha ou token nos parâmetros.',
      expected: 'Dados sensíveis vão no corpo de um POST ou em cabeçalho, nunca na URL.',
      acceptance: 'Nenhuma rota recebe senha, token ou dado pessoal em parâmetro de URL.',
      learn: [{ label: 'OWASP · Exposição de informação pela URL', url: 'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url' }],
      attack: [],
    },
  },
  {
    match: /x-powered-by|server leaks|versão do servidor|comentários suspeitos|suspicious comments|divulgação de informa|information disclosure|vaza informa/i,
    guide: {
      name: 'Exposição de informação', cwe: 200,
      what: 'A resposta mostra detalhes internos: tecnologia e versão, comentários do desenvolvedor, mensagens de erro.',
      impact: 'Facilita o próximo passo do ataque: com a versão exata, basta procurar falhas conhecidas dela.',
      verify: 'Veja a linha marcada na evidência (cabeçalho ou comentário) na resposta da página.',
      expected: 'A resposta não revela tecnologia, versão nem comentários internos.',
      acceptance: 'O cabeçalho/comentário citado não aparece mais em nenhuma resposta.',
      learn: [
        { label: 'PortSwigger Academy · Exposição de informação', url: `${PORTSWIGGER}information-disclosure` },
        { label: 'OWASP Cheat Sheet · Cabeçalhos HTTP de segurança', url: `${CHEAT}HTTP_Headers_Cheat_Sheet.html` },
      ],
      attack: [{ label: 'PortSwigger · Explorar exposição de informação', url: `${PORTSWIGGER}information-disclosure/exploiting` }],
    },
  },
  {
    match: /x-content-type-options|strict-transport|hsts|permissions[\s-]*policy|referrer[\s-]*policy|cabeçalho|header/i,
    guide: {
      name: 'Cabeçalho de segurança ausente', cwe: 693,
      what: 'Falta um cabeçalho HTTP que liga uma proteção do navegador (tipo de conteúdo, HTTPS obrigatório, permissões...).',
      impact: 'Cada cabeçalho fecha uma porta: sem eles, ataques como MIME sniffing ou rebaixamento para HTTP ficam possíveis.',
      verify: 'Veja os cabeçalhos da resposta (DevTools > Rede) e confira se o cabeçalho citado está lá.',
      expected: 'Todas as respostas enviam o cabeçalho com o valor recomendado.',
      acceptance: 'O cabeçalho citado aparece em todas as respostas (configurado no servidor ou no proxy, não página a página).',
      learn: [
        { label: 'OWASP Cheat Sheet · Cabeçalhos HTTP de segurança', url: `${CHEAT}HTTP_Headers_Cheat_Sheet.html` },
        { label: 'MDN · Cabeçalhos HTTP', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers' },
      ],
      attack: [],
    },
  },
  {
    match: /\.git|backup|arquivo exposto|exposed file|directory listing|listagem/i,
    guide: {
      name: 'Arquivo ou pasta exposta', cwe: 538,
      what: 'Um arquivo que não deveria ser público (pasta .git, backup, configuração) pode ser baixado pelo navegador.',
      impact: 'Baixar o código-fonte, senhas e chaves que estão nesses arquivos.',
      verify: 'Abra a URL da evidência no navegador e veja se o arquivo é entregue.',
      expected: 'O servidor responde 404 (ou 403) para esses caminhos.',
      acceptance: 'Arquivos de controle de versão, backup e configuração ficam fora da pasta pública ou bloqueados no servidor.',
      learn: [{ label: 'PortSwigger Academy · Exposição de informação', url: `${PORTSWIGGER}information-disclosure` }],
      attack: [{ label: 'PayloadsAllTheThings · Insecure Source Code Management', url: `${PATT}Insecure%20Source%20Code%20Management` }],
    },
  },
  {
    match: /cve-\d|componente vulnerável|vulnerable component|outdated|versão vulnerável/i,
    guide: {
      name: 'Componente com vulnerabilidade conhecida', cwe: 1104,
      what: 'A versão de um software ou biblioteca usada tem uma falha pública (CVE), com exploração conhecida.',
      impact: 'Depende da CVE; muitas permitem invadir sem esforço, com exploits prontos na internet.',
      verify: 'Confira a versão instalada e compare com a versão corrigida informada na CVE.',
      expected: 'A versão em uso é igual ou mais nova que a corrigida.',
      acceptance: 'O componente foi atualizado para a versão corrigida e a varredura não aponta mais a CVE.',
      learn: [{ label: 'OWASP Top 10 · A06 Componentes vulneráveis', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' }],
      attack: [{ label: 'Exploit-DB (busca por CVE)', url: 'https://www.exploit-db.com/' }],
    },
  },
  {
    match: /cors|cross[\s-]*origin/i,
    guide: {
      name: 'CORS permissivo', cwe: 942,
      what: 'O servidor libera que outros sites leiam as respostas da API usando a sessão da vítima.',
      impact: 'Um site malicioso lê dados privados da vítima pela sua API.',
      verify: 'Envie a requisição com Origin: https://exemplo-malicioso.com e veja se Access-Control-Allow-Origin devolve essa origem.',
      expected: 'Só origens confiáveis recebem permissão; credenciais nunca com origem curinga.',
      acceptance: 'Access-Control-Allow-Origin vem de uma lista permitida fixa.',
      learn: [{ label: 'PortSwigger Academy · CORS', url: `${PORTSWIGGER}cors` }],
      attack: [{ label: 'PayloadsAllTheThings · CORS Misconfiguration', url: `${PATT}CORS%20Misconfiguration` }],
    },
  },
  {
    match: /tls|ssl|certificad/i,
    guide: {
      name: 'TLS/SSL fraco', cwe: 326,
      what: 'A conexão HTTPS aceita protocolo ou cifra antigos, ou o certificado tem problema.',
      impact: 'Quem está no caminho (Wi-Fi público, provedor) pode ler ou alterar o tráfego.',
      verify: 'Teste o domínio no SSL Labs (ssllabs.com/ssltest) e confira protocolos e cifras.',
      expected: 'Só TLS 1.2+ com cifras fortes e certificado válido.',
      acceptance: 'TLS 1.0/1.1 e cifras fracas desligados; nota A no SSL Labs.',
      learn: [{ label: 'OWASP Cheat Sheet · Transport Layer Security', url: `${CHEAT}Transport_Layer_Security_Cheat_Sheet.html` }],
      attack: [],
    },
  },
];

const GENERIC: FlawGuide = {
  name: 'Falha de segurança', cwe: null,
  what: 'A ferramenta encontrou um comportamento que foge da boa prática de segurança (veja a descrição do achado).',
  impact: 'Depende do caso: a descrição e a severidade indicam o risco.',
  verify: 'Repita a requisição da evidência e confira o trecho marcado na resposta.',
  expected: 'O comportamento apontado não aparece mais.',
  acceptance: 'A varredura seguinte não aponta mais o achado.',
  learn: [{ label: 'OWASP Cheat Sheet Series (índice)', url: 'https://cheatsheetseries.owasp.org/' }],
  attack: [],
};

/** Guia da classe da falha (título, OWASP e regra), ou o genérico. */
export const guideFor = (finding: Pick<Finding, 'title' | 'owaspUrl' | 'ruleId' | 'cveId'>): FlawGuide => {
  const text = [finding.title, finding.ruleId, finding.cveId].filter(Boolean).join(' ');
  return CLASSES.find((c) => c.match.test(text))?.guide ?? GENERIC;
};

/** Link da categoria OWASP Top 10 ("A05:2021 – ..." → página oficial). */
export const owaspLink = (owasp: string | null | undefined): GuideLink | null => {
  const code = owasp?.match(/\bA(0[1-9]|10)\b/)?.[0];
  return code ? OWASP_TOP10[code] ?? null : null;
};

export const cweLink = (cwe: number | null): GuideLink | null =>
  cwe ? { label: `CWE-${cwe} (MITRE)`, url: `https://cwe.mitre.org/data/definitions/${cwe}.html` } : null;

/** Padrões que comprovam a falha (QA) e referências oficiais. */
export const standardLinks = (finding: Finding, guide: FlawGuide): GuideLink[] => {
  const links = [owaspLink(finding.owaspUrl), cweLink(guide.cwe)];
  if (finding.cveId) links.push({ label: `${finding.cveId} (NVD)`, url: `https://nvd.nist.gov/vuln/detail/${finding.cveId}` });
  return [...links.filter((l): l is GuideLink => Boolean(l)), ...guide.learn.filter((l) => l.url.includes('cheatsheetseries'))];
};

// ---------- Pentester: vetor CVSS explicado ----------

const CVSS_METRICS: Record<string, { name: string; values: Record<string, string> }> = {
  AV: { name: 'Vetor de ataque', values: { N: 'Rede (pela internet)', A: 'Rede adjacente', L: 'Local', P: 'Físico' } },
  AC: { name: 'Complexidade', values: { L: 'Baixa', H: 'Alta' } },
  PR: { name: 'Privilégio exigido', values: { N: 'Nenhum (sem login)', L: 'Baixo (usuário comum)', H: 'Alto (admin)' } },
  UI: { name: 'Interação da vítima', values: { N: 'Nenhuma', R: 'Precisa (ex.: clicar num link)' } },
  S: { name: 'Escopo', values: { U: 'Não muda', C: 'Muda (afeta outros componentes)' } },
  C: { name: 'Confidencialidade', values: { N: 'Nenhum impacto', L: 'Baixo', H: 'Alto' } },
  I: { name: 'Integridade', values: { N: 'Nenhum impacto', L: 'Baixo', H: 'Alto' } },
  A: { name: 'Disponibilidade', values: { N: 'Nenhum impacto', L: 'Baixo', H: 'Alto' } },
};

export interface CvssPart {
  metric: string;
  name: string;
  value: string;
  meaning: string;
}

export const explainCvss = (vector: string | null | undefined): CvssPart[] =>
  (vector ?? '')
    .split('/')
    .map((part) => part.split(':'))
    .filter(([metric, value]) => metric in CVSS_METRICS && value)
    .map(([metric, value]) => ({
      metric,
      name: CVSS_METRICS[metric].name,
      value,
      meaning: CVSS_METRICS[metric].values[value] ?? value,
    }));

// ---------- QA: texto do ticket ----------

export interface TicketInput {
  finding: Finding;
  guide: FlawGuide;
  severityLabel: string;
  targetUrl: string;
  environment: string;
  locations: string[];
  /** requisição pronta (curl) da primeira ocorrência com prova */
  reproduction: string | null;
  /** linha da resposta que prova a falha, sem marcadores */
  evidenceLine: string | null;
}

/** Ticket em texto simples (cola em Jira, GitHub, Azure DevOps ou e-mail). */
export const buildTicket = (t: TicketInput): string => {
  const f = t.finding;
  const refs = standardLinks(f, t.guide).map((l) => `- ${l.label}: ${l.url}`);
  const where = t.locations.slice(0, 8).map((l) => `- ${l}`);
  if (t.locations.length > 8) where.push(`- ... e mais ${t.locations.length - 8} local(is)`);
  const steps = t.reproduction
    ? [`1. Execute: ${t.reproduction}`, '2. Observe na resposta o trecho indicado em "Resultado obtido".']
    : [`1. ${t.guide.verify}`];
  return [
    `[Segurança][${t.severityLabel}] ${f.title}`,
    '',
    `Ambiente: ${t.targetUrl} (${t.environment})`,
    `Severidade: ${t.severityLabel}${f.cvssScore !== null ? ` · CVSS ${f.cvssScore.toFixed(1)}` : ''}${f.cvssVector ? ` (${f.cvssVector})` : ''}`,
    `Classificação: ${[f.owaspUrl, t.guide.cwe ? `CWE-${t.guide.cwe}` : null].filter(Boolean).join(' · ') || '—'}`,
    '',
    'Onde ocorre',
    ...(where.length ? where : ['- (ver relatório)']),
    '',
    'Descrição',
    f.description?.trim() || t.guide.what,
    '',
    'Passos para reproduzir',
    ...steps,
    '',
    'Resultado esperado',
    t.guide.expected,
    '',
    'Resultado obtido',
    t.evidenceLine ? `A resposta contém: ${t.evidenceLine}` : t.guide.impact,
    '',
    'Critério de aceite',
    t.guide.acceptance,
    '',
    'Referências',
    ...(refs.length ? refs : ['- (ver relatório do Checkop)']),
  ].join('\n');
};
