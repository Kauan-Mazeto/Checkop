# Como rodar o Checkop localmente (Windows)

Passo a passo para deixar o projeto funcionando como no ambiente de desenvolvimento: varredura web (ZAP + Nuclei), análise de código (Semgrep + Gitleaks), painel, relatórios e o laboratório de testes.

Tempo estimado: **40 a 60 minutos** na primeira vez, a maior parte esperando downloads (~600 MB entre ferramentas e dependências).

---

## 0. Visão geral: o que vai rodar

São 5 processos, cada um num terminal:

| Serviço | Porta | O que faz |
|---|---|---|
| **OWASP ZAP** | 8091 | Mapeia o site e testa ataques (SQLi, XSS...) |
| **Motor Python** (FastAPI) | 8010 | Executa ZAP, Nuclei, Subfinder, Semgrep e Gitleaks |
| **Backend** (Node/Express + Prisma/SQLite) | 8080 | API, login, planos, banco de dados |
| **Front-end** (Angular) | 4200 | A interface. Encaminha `/api` para o backend |
| **Laboratório vulnerável** | 3000 | Site de teste feito para ter falhas (opcional) |

Você usa o sistema em **http://localhost:4200**.

---

## 1. Pré-requisitos

Instale nesta ordem. Em cada instalador, aceite a opção de **adicionar ao PATH**.

| Programa | Versão | Onde baixar | Observação |
|---|---|---|---|
| **Git** | qualquer recente | https://git-scm.com/download/win | |
| **Node.js** | **22 LTS** (22.15 ou mais nova) | https://nodejs.org | Instala junto o `npm` |
| **Python** | **3.13** | https://www.python.org/downloads/ | Marque **"Add python.exe to PATH"** na primeira tela |
| **Java (JDK)** | **17 ou mais novo** (usamos o 25) | https://adoptium.net (Temurin) | O ZAP precisa de Java. Marque "Set JAVA_HOME" |
| **Microsoft Edge** | já vem no Windows | | O ZAP usa o Edge para explorar sites Angular/React |

Depois de instalar, **feche e abra o PowerShell** e confira:

```powershell
git --version
node --version     # v22.x
npm --version
python --version   # Python 3.13.x
java -version      # 17 ou mais
```

> Se `python` abrir a Microsoft Store: vá em *Configurações → Aplicativos → Configurações avançadas de aplicativos → Aliases de execução* e desligue os dois "Instalador de aplicativo" do Python. Depois feche e abra o terminal.

---

## 2. Baixar o projeto

```powershell
cd "$HOME\Desktop"          # ou a pasta que preferir
git clone https://github.com/Kauan-Mazeto/Checkop.git
cd Checkop
```

> Evite colocar o projeto dentro do OneDrive. A sincronização pode travar o banco SQLite e a pasta `node_modules`.

Todos os comandos a seguir partem da **raiz do projeto** (a pasta `Checkop`).

---

## 3. Ferramentas de varredura (ZAP, Nuclei, Subfinder, Gitleaks)

Elas ficam em `backend\tools\`, uma pasta **fora do git**: cada pessoa baixa a sua. O script baixa as mesmas versões usadas no desenvolvimento e também os ~14 mil templates do Nuclei:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\baixar-ferramentas.ps1
```

São ~350 MB. Ao final, deve aparecer `[ok]` para `nuclei`, `subfinder`, `gitleaks` e `zap`.

| Ferramenta | Versão | Fica em |
|---|---|---|
| OWASP ZAP | 2.17.0 | `backend\tools\zap\ZAP_2.17.0\` |
| Nuclei | 3.11.1 | `backend\tools\nuclei\nuclei.exe` (templates em `%USERPROFILE%\nuclei-templates`) |
| Subfinder | 2.17.0 | `backend\tools\subfinder\subfinder.exe` |
| Gitleaks | 8.30.1 | `backend\tools\gitleaks\gitleaks.exe` |

---

## 4. Motor Python

```powershell
cd backend\src\py\security_engine
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd ..\..\..\..
```

Isso instala FastAPI, Uvicorn e o **Semgrep**, usado na análise de código. Confira:

```powershell
semgrep --version
```

> Se der "semgrep não é reconhecido", a pasta `Scripts` do Python não está no PATH. Rode `python -m site --user-base`, acrescente `\Python313\Scripts` ao caminho mostrado, coloque o resultado no PATH do Windows e reabra o terminal.

O motor **não tem `.env` próprio**: ele lê o `backend\.env` do próximo passo.

---

## 5. Backend

### 5.1 Dependências

```powershell
cd backend
npm install
```

### 5.2 Configuração (`.env`)

```powershell
copy .env.example .env
notepad .env
```

Preencha os campos **obrigatórios**. Para os segredos, gere um valor aleatório para cada um (rode o comando uma vez por campo e cole o resultado):

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

| Campo | O que colocar |
|---|---|
| `JWT_SECRET` | valor gerado |
| `RESET_CODE_SECRET` | valor gerado |
| `ENGINE_TOKEN` | valor gerado (o backend e o motor usam o mesmo, os dois leem deste arquivo) |
| `ZAP_API_KEY` | valor gerado (o script de inicialização passa esse valor ao ZAP) |

Os demais já vêm com o valor certo para uso local (`DATABASE_URL`, `PORT=8080`, `CLIENT_URL=http://localhost:4200`, `MODO_DEV="DEV"`, `ZAP_API_URL=http://localhost:8091`). Os opcionais estão na [seção 10](#10-recursos-opcionais).

> **Nunca** envie seu `.env` para o git nem para outra pessoa. Ele já está no `.gitignore`.

### 5.3 Banco de dados

Cria o arquivo `backend\prisma\database.db` com todas as tabelas:

```powershell
npx prisma migrate deploy
npx prisma generate
cd ..
```

O primeiro comando deve terminar com *"All migrations have been successfully applied"*.

---

## 6. Front-end

```powershell
cd front-end
npm install
cd ..
```

O front não tem `.env`. Em desenvolvimento ele chama `/api`, e o `proxy.conf.json` encaminha para o backend em `localhost:8080`.

---

## 7. Subir tudo

### Opção A: um comando (recomendado)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\iniciar-tudo.ps1
```

Abre 5 janelas (ZAP, Motor, Backend, Front, Lab). Para subir sem o laboratório, acrescente `-SemLab`.

### Opção B: manual, um terminal por serviço

```powershell
# 1) ZAP: troque SUA_CHAVE pelo ZAP_API_KEY do .env
cd backend\tools\zap\ZAP_2.17.0
.\zap.bat -daemon -host 127.0.0.1 -port 8091 -config api.key=SUA_CHAVE

# 2) Motor
cd backend\src\py\security_engine
python -m uvicorn app.main:app --host 127.0.0.1 --port 8010

# 3) Backend
cd backend
npm start

# 4) Front
cd front-end
npx ng serve

# 5) Laboratório (opcional)
cd backend\lab
node lab-vulneravel.mjs
```

### Como saber que está tudo no ar

| Janela | Mensagem de pronto |
|---|---|
| ZAP | `ZAP is now listening on 127.0.0.1:8091` (leva de 15 a 30 s) |
| Motor | `Uvicorn running on http://127.0.0.1:8010` |
| Backend | `Servidor Checkop rodando na porta 8080` |
| Front | `Local: http://localhost:4200/` |
| Lab | `lab vulnerável em http://127.0.0.1:3000` |

Conferência rápida: http://127.0.0.1:8010/health deve responder `{"status":"ok"}`.

> Na primeira varredura, o ZAP baixa sozinho alguns complementos (as regras beta). É preciso internet nesse momento.

---

## 8. Primeiro acesso

1. Abra **http://localhost:4200** e clique em **Criar conta**: nome, e-mail, senha, perfil de uso (QA, Dev, Pentester ou Estudante) e o aceite dos Termos.
2. Para liberar todos os recursos, vá em **Planos** e mude para **Premium**. É uma demonstração, sem cobrança.
3. Endereços locais (`localhost`, `127.0.0.1`) **não precisam** de verificação de domínio. Domínios públicos precisam ser verificados em **Domínios** antes de uma varredura com ataque.

---

## 9. Teste rápido: está tudo funcionando?

Com o laboratório rodando:

| # | O que fazer | Resultado esperado |
|---|---|---|
| 1 | **Nova varredura** → `http://localhost:3000` → **Injeção de SQL** | Em poucos minutos: **1 Crítico: SQL Injection** em `/item?id=` |
| 2 | Nova varredura → **Arquivos sensíveis expostos** | O Nuclei acha `/.env` e `/.git/config` |
| 3 | Nova varredura → **Varredura completa** | Achados do ZAP e do Nuclei (XSS, redirecionamento aberto, cabeçalhos, cookie) |
| 4 | **Análise de código** → escolha uma linguagem → **Carregar exemplo** → **Analisar** | Achados com a linha marcada e "Como corrigir" |
| 5 | Detalhe de uma varredura → **Exportar PDF / JSON**; Painel → **Exportar** | Arquivos baixados |
| 6 | Durante uma varredura completa → **Cancelar varredura** | Fica "Cancelada", com o que já tinha sido encontrado |

> O laboratório é **propositalmente vulnerável** e só aceita conexões do próprio computador (127.0.0.1). Não o exponha na rede.
>
> Só faça varreduras em sistemas seus ou com autorização por escrito do responsável. Testar sistema alheio é crime (art. 154-A do Código Penal).

---

## 10. Recursos opcionais

Tudo funciona sem eles; cada um só liga uma parte extra. Edite o `backend\.env` e **reinicie o backend e o motor**.

### Login com Google
1. No Google Cloud Console (https://console.cloud.google.com/apis/credentials), crie uma **ID do cliente OAuth** do tipo *Aplicativo da Web*.
2. Em **Origens JavaScript autorizadas**, adicione `http://localhost:4200`.
3. Em **Tela de consentimento OAuth → Usuários de teste**, adicione os e-mails que vão logar (no modo teste, só eles conseguem).
4. Cole o ID em `GOOGLE_CLIENT_ID`.

> Alternativa: quem já tem o client configurado pode compartilhar o mesmo `GOOGLE_CLIENT_ID` (ele não é segredo) e adicionar o seu e-mail como usuário de teste.

### E-mail (recuperação de senha e aviso de varredura concluída)
Preencha `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` e `MAIL_FROM`. No Gmail: `smtp.gmail.com`, porta `587`, e uma **senha de app** (https://myaccount.google.com/apppasswords), não a senha normal. Sem SMTP, o código de recuperação aparece no terminal do backend.

### Tradução dos achados
Sem configuração, usa o MyMemory (grátis, cerca de 5 mil caracteres por dia). Para mais qualidade, crie uma chave grátis do DeepL e coloque em `DEEPL_API_KEY`. Ou coloque seu e-mail em `MYMEMORY_EMAIL`, que sobe o limite para 50 mil.

### Correção com IA (Claude)
Crie uma chave em https://console.anthropic.com e coloque em `ANTHROPIC_API_KEY`. Isso libera **"Gerar correção com IA"** em cada achado e **"Corrigir o arquivo inteiro com IA"**, que usa créditos (compra demonstrativa na própria tela). O uso da API da Anthropic é cobrado na conta dona da chave.

---

## 11. Testes automatizados

```powershell
# backend (API Node)
cd backend
npm test

# motor Python
cd src\py\security_engine
python -m pytest -q        # ou: python -m unittest discover -s tests -t .

# front-end (Karma; usa o Edge no lugar do Chrome)
cd front-end
$env:CHROME_BIN = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
npx ng test --watch=false --browsers=ChromeHeadless
```

> O `pytest` não vem no `requirements.txt`: instale com `python -m pip install pytest`, ou use o comando `unittest` indicado.

---

## 12. Depois de um `git pull`

Sempre que puxar mudanças:

```powershell
cd backend
npm install
npx prisma migrate deploy
npx prisma generate
cd ..\front-end
npm install
cd ..\backend\src\py\security_engine
python -m pip install -r requirements.txt
```

Depois **reinicie o motor e o backend**; eles não recarregam código sozinhos. O front (`ng serve`) recarrega sozinho; se a tela ficar estranha, use **Ctrl+Shift+R** no navegador.

---

## 13. Problemas comuns

| Sintoma | Causa provável | Solução |
|---|---|---|
| Backend fecha dizendo que falta variável | `.env` incompleto | Preencha os obrigatórios da seção 5.2 |
| "Rota não encontrada" ou função nova não aparece | Backend ou motor com código antigo | `Ctrl+C` e suba de novo (seção 12) |
| `The table ... does not exist` | Banco sem as migrações | `cd backend` → `npx prisma migrate deploy` |
| ZAP não sobe: porta em uso | Outro programa na 8091 | Troque a porta no comando do ZAP **e** em `ZAP_API_URL` |
| Varredura com "ZAP indisponível" | ZAP não terminou de subir ou a chave difere | Espere o `listening`; confira se o `api.key` é o mesmo `ZAP_API_KEY` |
| "O Nuclei não conseguiu acessar o alvo" | Alvo fora do ar | Confira se o site (ou o laboratório) está rodando |
| "Regras do ZAP indisponíveis: 40024, 90018" | Regras que não existem no ZAP 2.17 | Normal, pode ignorar |
| Análise de código falha | Semgrep fora do PATH ou sem internet (ele baixa as regras oficiais) | `semgrep --version`; confira a conexão |
| Botão do Google não aparece | Sem `GOOGLE_CLIENT_ID` | Seção 10 |
| Google: "Erro 401 disabled_client" / "acesso bloqueado" | Client desativado, ou e-mail fora dos usuários de teste | Crie outro client ou adicione o e-mail (seção 10) |
| Botões de IA não aparecem | Sem `ANTHROPIC_API_KEY`, ou plano Free | Seção 10; mude para Premium |
| `npm` / `node` não reconhecido | Node fora do PATH | Reinstale o Node e reabra o terminal |
| Script `.ps1` bloqueado | Política de execução do Windows | Use `powershell -ExecutionPolicy Bypass -File ...` como indicado |
| Tela travada (nada clica) | Versão antiga da página em cache | **Ctrl+Shift+R** |

---

## 14. O que nunca vai para o git

Já estão no `.gitignore`. Mantenha assim:

- `backend/.env`: seus segredos;
- `backend/prisma/database.db`: contém dados pessoais (e-mails, IPs), por causa da LGPD;
- `backend/tools/`: os binários das ferramentas, que cada um baixa;
- `node_modules/`.

---

## Estrutura do projeto (resumo)

```
Checkop/
├─ SETUP.md                     ← este guia
├─ scripts/
│  ├─ baixar-ferramentas.ps1    ← baixa ZAP, Nuclei, Subfinder, Gitleaks
│  └─ iniciar-tudo.ps1          ← sobe os 5 serviços
├─ backend/
│  ├─ .env.example              ← modelo do .env
│  ├─ prisma/                   ← schema e migrações do banco
│  ├─ src/                      ← API Node (controllers, rotas, regras de plano...)
│  │  └─ py/security_engine/    ← motor Python (FastAPI) e regras do Checkop
│  ├─ lab/                      ← laboratório vulnerável para testes
│  ├─ docs/                     ← requisitos e histórico de alterações
│  └─ tools/                    ← ferramentas baixadas (fora do git)
└─ front-end/                   ← Angular
```
