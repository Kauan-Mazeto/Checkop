"""Título e correção em português por classe de falha (CWE).

Usado para apresentar QUALQUER achado de forma clara, independente de qual regra
ou linguagem o detectou: o nome técnico da regra ("formatted-sql-string") vira
"SQL Injection" e a correção deixa de ser genérica. Não detecta nada sozinho.
"""

import re

CWE_INFO: dict[str, tuple[str, str]] = {
    "89": ("SQL Injection", "Use consultas parametrizadas (prepared statements / placeholders) e nunca concatene entrada do usuário na SQL."),
    "564": ("SQL Injection (ORM)", "Use os métodos parametrizados do ORM em vez de montar consultas cruas com entrada do usuário."),
    "943": ("Injeção em consulta (NoSQL/LDAP/XPath)", "Valide a entrada e use as APIs de consulta parametrizada da biblioteca."),
    "79": ("Cross-Site Scripting (XSS)", "Escape a saída conforme o contexto (HTML, atributo, JS) ou use um template que escapa por padrão; evite innerHTML."),
    "78": ("Injeção de comandos do sistema", "Não monte comandos de shell com entrada do usuário; use APIs com lista de argumentos e allowlist."),
    "77": ("Injeção de comandos", "Não monte comandos com entrada do usuário; use APIs com lista de argumentos e allowlist."),
    "94": ("Injeção de código (eval)", "Não execute código montado a partir de entrada do usuário (eval, Function, exec); use parsers seguros."),
    "95": ("Injeção de código (eval)", "Não execute código montado a partir de entrada do usuário (eval, Function, exec); use parsers seguros."),
    "22": ("Path Traversal", "Normalize o caminho e garanta que ele fica dentro de um diretório base permitido; rejeite '..' e caminhos absolutos."),
    "23": ("Path Traversal", "Normalize o caminho e garanta que ele fica dentro de um diretório base permitido."),
    "73": ("Controle externo de caminho de arquivo", "Não use entrada do usuário direto em caminhos; mapeie para nomes conhecidos (allowlist)."),
    "611": ("XML External Entity (XXE)", "Desabilite DTD e entidades externas no parser XML."),
    "502": ("Desserialização insegura", "Não desserialize dados não confiáveis; prefira JSON com validação de schema."),
    "918": ("Server-Side Request Forgery (SSRF)", "Valide o destino contra uma allowlist de hosts e bloqueie endereços internos."),
    "601": ("Open Redirect", "Redirecione apenas para caminhos internos ou para uma allowlist de domínios."),
    "352": ("Cross-Site Request Forgery (CSRF)", "Use tokens anti-CSRF e cookies SameSite nas operações que alteram estado."),
    "798": ("Credencial fixa no código", "Remova o segredo do código e carregue por variável de ambiente ou cofre de segredos; troque a credencial exposta."),
    "259": ("Senha fixa no código", "Remova a senha do código e carregue por variável de ambiente ou cofre de segredos; troque a senha exposta."),
    "321": ("Chave criptográfica fixa no código", "Gere a chave fora do código e carregue de um cofre de segredos ou KMS."),
    "327": ("Criptografia fraca ou insegura", "Use algoritmos e modos modernos (ex.: AES-GCM); evite ECB, DES, RC4, MD5 e SHA-1."),
    "326": ("Chave criptográfica fraca", "Use tamanhos de chave adequados (ex.: AES-256, RSA ≥ 2048 bits)."),
    "328": ("Hash fraco", "Use SHA-256 ou superior; para senhas, use bcrypt, scrypt ou Argon2."),
    "916": ("Hash de senha fraco", "Armazene senhas com bcrypt, scrypt ou Argon2, com salt."),
    "330": ("Aleatoriedade insegura", "Use um gerador criptográfico (SecureRandom, crypto.randomBytes, secrets) para tokens e chaves."),
    "338": ("Aleatoriedade insegura", "Use um gerador criptográfico (SecureRandom, crypto.randomBytes, secrets) para tokens e chaves."),
    "295": ("Validação de certificado TLS desativada", "Não desative a verificação de certificado; configure a cadeia de confiança corretamente."),
    "319": ("Dados trafegando sem criptografia", "Use HTTPS/TLS para toda comunicação com dados sensíveis."),
    "209": ("Exposição de detalhes de erro", "Mostre mensagens genéricas ao usuário e registre os detalhes só em log interno."),
    "532": ("Dado sensível em log", "Não registre senhas, tokens ou dados pessoais em log; mascare os valores."),
    "200": ("Exposição de informação sensível", "Restrinja o que é retornado ao cliente e remova dados internos das respostas."),
    "614": ("Cookie sem o atributo Secure", "Marque cookies de sessão com Secure, HttpOnly e SameSite."),
    "1004": ("Cookie sem o atributo HttpOnly", "Marque cookies de sessão com HttpOnly, Secure e SameSite."),
    "1333": ("Expressão regular vulnerável a ReDoS", "Evite regex com backtracking exponencial; limite o tamanho da entrada."),
    "400": ("Consumo de recursos sem limite", "Limite tamanho de entrada, tempo de processamento e taxa de requisições."),
    "284": ("Controle de acesso inadequado", "Verifique a permissão do usuário no servidor em toda operação."),
    "639": ("Acesso direto inseguro a objeto (IDOR)", "Confirme que o recurso pertence ao usuário autenticado antes de retornar ou alterar."),
    "915": ("Atribuição em massa (mass assignment)", "Aceite apenas os campos permitidos (allowlist) ao criar ou atualizar objetos."),
}

_CWE_NUMBER = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def cwe_numbers(cwe_metadata) -> list[str]:
    """['CWE-89: ...'] ou 'CWE-89' -> ['89']"""
    values = cwe_metadata if isinstance(cwe_metadata, list) else [cwe_metadata]
    numbers: list[str] = []
    for value in values:
        for match in _CWE_NUMBER.findall(str(value or "")):
            if match not in numbers:
                numbers.append(match)
    return numbers


def describe(cwe_ids: list[str]) -> tuple[str, str] | None:
    """(título, correção) da primeira CWE conhecida, ou None."""
    for cwe in cwe_ids:
        if cwe in CWE_INFO:
            return CWE_INFO[cwe]
    return None
