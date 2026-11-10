# 02 — Correções de segurança B1–B10

**Data:** 2026-11-09 · **Status:** Implementado e testado · **Requisitos:** RF-47, RNF-07, RNF-10, RNF-24, RNF-25

## 1. Problema
A revisão do backend ([01](../01-levantamento-de-pendencias/README.md)) encontrou falhas na **própria** plataforma. Uma ferramenta de segurança precisa ser segura: estas falhas permitiriam usar o Checkop contra a própria infraestrutura, vazavam dados pessoais ou geravam relatórios errados.

## 2. Problemas e correções

| # | Problema | Impacto | Correção |
|---|---|---|---|
| B1 | A função de classificação OWASP calculava a categoria pelas tags, mas nunca a retornava | Quase todo achado do ZAP e Nuclei saía como "A06 – Componentes Desatualizados", deixando errados os gráficos e o compliance LGPD/PCI | Retorno da categoria encontrada (`mapping.py`) |
| B2 | Banco SQLite (`database.db`) e `__pycache__` versionados no git | E-mails, hashes de senha e IPs no repositório, contra a LGPD | Removidos do versionamento e adicionados ao `.gitignore` |
| B3 | Domínio público que resolve para IP interno era aceito | SSRF / DNS rebinding: usar o Checkop para atacar a rede interna do servidor | Varredura é registrada (auditoria), mas a execução é recusada (403) |
| B4 | Motor Python sem autenticação | Qualquer um que alcançasse a porta 8010 disparava varreduras | Header `X-Engine-Token` obrigatório; o motor nem sobe sem o token |
| B5 | O DNS validado no cadastro podia mudar até a execução | Brecha de DNS rebinding | DNS conferido de novo no momento do `run` |
| B6 | `/api/sast` sem limite (10 MB e até 3 min por chamada) | Negação de serviço contra o próprio Checkop | Limite de 10 análises por hora |
| B7 | Login com Google criava a conta sem o aceite dos termos | Sem consentimento registrado (LGPD) e sem o termo de responsabilidade do TCC | Primeiro login Google exige `termsAccepted: true` (`code: TERMS_REQUIRED`) |
| B8 | Registros de login mantinham o e-mail após a exclusão da conta | Contradizia a política de privacidade | E-mail substituído por `[conta-excluida]` na mesma transação da exclusão |
| B9 | Segredos obrigatórios (`RESET_CODE_SECRET`, `EXPIRES_IN`) não eram checados no boot | Erro 500 em login/recuperação de senha | Validação no boot, com o nome da variável ausente |
| B10 | Erro do SAST repassava a mensagem interna do motor ao cliente | Vazamento de detalhes internos (RNF-25) | Mensagem genérica ao cliente; detalhe só no log |

**Bug extra:** `dotenv.config()` rodava depois dos imports (em ESM os imports executam antes), então variáveis lidas no carregamento dos módulos, como `SECURITY_ENGINE_URL`, ignoravam o `.env`. Corrigido com `import 'dotenv/config'` como primeiro import do `server.js`.

## 3. Decisões tomadas
| Decisão | Opções | Escolha e motivo |
|---|---|---|
| Alvos localhost/rede privada | Bloquear sempre · flag de ambiente · bloquear só suspeitos | **Só suspeitos.** Mantém o uso local com DVWA/Juice Shop, como o TCC prevê |
| Banco no histórico do git | Só parar de versionar · reescrever histórico | **Só parar de versionar.** Reescrever o histórico é destrutivo para o outro autor |
| Framework de testes | Nativos · Jest + pytest | **Nativos** (`node:test` e `unittest`), sem dependência nova |
| Correção completa do B5 | Fixar o IP na varredura · revalidar no run | **Revalidar no run.** ZAP e Nuclei resolvem DNS sozinhos e fixar o IP quebra HTTPS (SNI) |

## 4. Arquivos alterados
- `src/py/security_engine/app/mapping.py` (B1), `app/main.py` (B4)
- `src/lib/py/security_engine_client.js`, `src/lib/py/sast_client.js` (B4)
- `src/controllers/scan_controllers.js` (B3, B5)
- `src/controllers/auth_controllers.js`, `src/validators/auth_validator.js` (B7, B8)
- `src/middlewares/rate_limit_middleware.js`, `src/routes/sast_routes.js` (B6)
- `src/server.js` (B9, dotenv), `src/controllers/sast_controllers.js` (B10)
- `.gitignore` (B2), `package.json` (scripts de teste)

**Variável nova:** `ENGINE_TOKEN`, com o mesmo valor no `.env` do Node e no ambiente do motor Python. Subir o motor com:
```bash
ENGINE_TOKEN=... uvicorn app.main:app --host 127.0.0.1 --port 8010
```

## 5. Como foi validado
- 21 testes Node: detector de ambiente, bloqueio do run, aceite de termos no Google, anonimização na exclusão de conta.
- 10 testes Python: classificação OWASP e autenticação do motor.
- **Teste de mutação do B1:** os testes rodados contra a versão antiga do `mapping.py` falham (4 de 6), o que prova que detectam o bug.
- Boot real sem `ENGINE_TOKEN`: o servidor recusa subir e informa a variável ausente.

## 6. Limitações e riscos conhecidos
- Com `localhost` liberado, quem usa o servidor de produção ainda consegue varrer o próprio servidor. Vale citar como limitação no TCC.
- A revalidação de DNS reduz, mas não elimina, a janela de DNS rebinding.
- O `database.db` continua nos commits antigos do git.
- Ao puxar o commit da correção B2, o `database.db` local é apagado: faça backup antes ou recrie com `npm run prisma:push`.

## 7. Para os slides
- "Uma ferramenta de segurança também precisa ser segura": 10 falhas encontradas e corrigidas na própria plataforma.
- Destaque: o bug de classificação OWASP (B1) fazia todo relatório sair com a categoria errada. Encontrado na revisão e travado por teste automatizado.
- Proteção contra SSRF: o Checkop não pode ser usado para atacar a rede interna onde está hospedado.
- Defesa em profundidade: motor de varredura isolado, acessível só pela API com token.
