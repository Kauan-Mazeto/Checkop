// Política de Privacidade do Checkop (LGPD, Lei nº 13.709/2018).
// Descreve o que o sistema faz de fato; ao mudar coleta, compartilhamento ou
// retenção no código, atualize este texto e a data.
//
// Texto elaborado pela equipe do TCC. Antes de uso comercial, deve ser
// revisado por advogado. Contatos (e-mails) são provisórios.
//
// Formato: markdown simples lido por front-end/src/app/shared/ui/markdown.ts.
export const PRIVACY_POLICY = {
  version: '2.3',
  lastUpdated: '2026-11-27',
  content: `
# Política de Privacidade

Esta Política explica quais dados pessoais o Checkop coleta, para quais finalidades, com quem eles são compartilhados, por quanto tempo são mantidos e como você pode exercer os seus direitos, nos termos da Lei Geral de Proteção de Dados Pessoais (LGPD, Lei nº 13.709/2018) e do Marco Civil da Internet (Lei nº 12.965/2014).

> Resumo: coletamos apenas o necessário para a sua conta, para executar as varreduras que você solicita e para comprovar que cada teste foi autorizado. Não vendemos dados, não usamos os seus dados para publicidade e você pode excluir a sua conta a qualquer momento.

## 1. Quem é o controlador
O controlador dos dados pessoais é a equipe responsável pelo Checkop, projeto acadêmico desenvolvido como Trabalho de Conclusão de Curso. Para assuntos de privacidade, o canal de contato com o encarregado pelo tratamento de dados é **privacidade@checkop.com.br**.

## 2. Dados que coletamos
### 2.1. Dados de cadastro
- Nome, e-mail e perfil de uso (QA, Desenvolvedor, Pentester ou Estudante).
- Senha, armazenada exclusivamente como hash criptográfico (bcrypt), nunca em texto legível.
- Plano contratado (Free ou Premium).
- Registro do aceite dos Termos de Uso, com a versão aceita, data, hora, endereço IP e navegador.
- No login com Google: nome, e-mail, a confirmação de que o e-mail foi verificado e um identificador da conta, recebidos do Google. Não recebemos a sua senha do Google.

### 2.2. Dados de uso da plataforma
- Alvos cadastrados (domínios ou hosts) e o resultado da verificação de propriedade.
- Varreduras solicitadas: endereço analisado, tipo de teste, ambiente detectado, endereços IP resolvidos, status e horários.
- Resultados das varreduras: achados, severidade, evidências técnicas e recomendações. Em ambientes de produção, requisições, respostas e parâmetros sensíveis são ocultados (Modo Seguro).
- Declarações de autorização para varreduras, inclusive para a varredura ativa, com data, hora e endereço IP.

### 2.3. Registros de acesso e segurança
- Tentativas de login, com sucesso ou falha, endereço IP, navegador, data e hora.
- Registros de auditoria das ações relevantes na conta (alvos, varreduras, autorizações e trocas de plano).

### 2.4. Código enviado para análise
O código-fonte enviado para análise é processado nos servidores do Checkop apenas para gerar o resultado e **não é armazenado** no banco de dados após a resposta.

Para o histórico e os relatórios da análise de código (plano Premium), o Checkop guarda **somente o resumo de cada análise**, e nada além disso:
- data, duração e modo da análise (completa ou essencial);
- nome, linguagem e número de linhas de cada arquivo enviado;
- a quantidade de achados por severidade e por categoria;
- para cada achado: título, severidade, categoria, nome do arquivo, número da linha, identificador da regra e ferramentas que o apontaram.

Não são guardados: o conteúdo dos arquivos, o trecho de código vulnerável, as correções sugeridas (pela ferramenta ou pela IA), as descrições dos achados nem as conversas com a ajuda por IA. Você pode apagar uma análise ou o histórico inteiro a qualquer momento, na própria aba de análise de código.

Os recursos de IA usam **um** provedor de IA, escolhido na configuração do servidor: a **Anthropic** (modelo Claude) ou o **Google** (modelo Gemini). A tela de cada recurso mostra qual provedor está em uso antes do envio. A correção com IA envia código ao provedor sempre e somente quando você pede:
- **"Gerar correção com IA"** (em um achado): envia só as linhas em volta daquele achado, não o arquivo inteiro.
- **"Corrigir o arquivo inteiro com IA"** (recurso pago com créditos de IA): envia o arquivo analisado inteiro e a lista de achados dele, para devolver o arquivo completo corrigido.

### 2.5. Ajuda por IA
Na tela "Ajuda por IA" (recurso pago com créditos de IA), você escolhe uma varredura ou uma análise de código e escreve uma pergunta. Antes do envio, a tela mostra exatamente o que vai sair do Checkop. São enviados ao provedor de IA, a cada pergunta:
- a sua pergunta e as mensagens anteriores da mesma conversa;
- de uma **varredura**: o endereço analisado, o tipo de teste, o ambiente e, por achado, título, severidade, ferramenta, local (endereço da página, sem a parte da URL com a carga de teste, e o nome do parâmetro), CVE/CVSS, status da correção, descrição e recomendação. **Não** são enviadas as evidências técnicas (requisições, respostas e cargas de teste);
- de uma **análise de código**: o resumo guardado no histórico (item 2.4), sem nenhum código.

A conversa **não é gravada** no banco do Checkop: ela fica só na aba do seu navegador e some ao sair da tela. No registro de auditoria fica apenas que houve uma pergunta, sobre qual varredura ou análise e quantos créditos foram usados, nunca o texto.

### 2.6. Dados sobre terceiros nos resultados
As varreduras podem revelar informações presentes nos sistemas analisados. Esses dados são de responsabilidade do Usuário, que declara ter autorização sobre o Alvo, e são tratados apenas para compor o relatório solicitado.

## 3. Para que usamos os dados e com qual base legal
- **Criar e manter a sua conta, autenticar o acesso e prestar o serviço contratado:** execução de contrato (LGPD, art. 7º, V).
- **Executar as varreduras, gerar os relatórios e aplicar os recursos do seu plano:** execução de contrato (art. 7º, V).
- **Comprovar que cada varredura foi autorizada e prevenir o uso da plataforma para ataques a terceiros:** legítimo interesse e exercício regular de direitos (art. 7º, IX e VI).
- **Detectar e investigar acessos indevidos e proteger a sua conta:** legítimo interesse (art. 7º, IX).
- **Guardar os registros de acesso pelo prazo legal:** cumprimento de obrigação legal (art. 7º, II, e art. 15 do Marco Civil da Internet).
- **Enviar o código de redefinição de senha e o aviso de varredura concluída (que pode ser desligado a qualquer momento):** execução de contrato (art. 7º, V).

Não utilizamos os seus dados para publicidade, não traçamos perfis comerciais e não tomamos decisões automatizadas que produzam efeitos jurídicos sobre você.

## 4. Compartilhamento de dados
Os dados pessoais não são vendidos nem cedidos. Eles são compartilhados apenas nas situações abaixo, na medida do necessário:
- **Google:** quando você escolhe entrar com Google, para autenticar a sua identidade.
- **Provedor de e-mail:** o seu endereço de e-mail é enviado ao serviço de envio de mensagens para entregar o código de redefinição de senha e, se a opção estiver ligada em "Conta e privacidade", o aviso de varredura concluída (só com a contagem de falhas por severidade).
- **Serviços de tradução automática (DeepL ou MyMemory):** apenas os textos padronizados que descrevem as regras de segurança são enviados para tradução ao português. Nenhum dado da sua conta, endereço analisado ou código é enviado.
- **Provedor de IA (Anthropic, modelo Claude, ou Google, modelo Gemini, conforme a configuração do servidor):** somente quando você pede: na correção com IA da análise de código, as linhas em volta do achado ou, na correção completa, o arquivo analisado inteiro; na "Ajuda por IA", a pergunta e o resumo da varredura ou da análise escolhida, como descrito no item 2.5.
  - **Anthropic:** pelos termos comerciais dela, dados recebidos pela API não são usados, por padrão, para treinar os modelos.
  - **Google Gemini no plano gratuito da API:** pelos termos do Google, o conteúdo enviado **pode ser usado para melhorar os produtos do Google e pode passar por revisão humana**. Por isso, quando o Gemini estiver em uso, não envie dados pessoais nem segredos reais no código ou nas perguntas.
- **Infraestrutura de hospedagem:** onde a plataforma e o banco de dados são executados.
- **Autoridades:** mediante ordem judicial ou requisição legal, nos limites da lei.

As ferramentas de análise (OWASP ZAP, Nuclei, Subfinder, Semgrep e Gitleaks) são executadas nos servidores do próprio Checkop.

## 5. Transferência internacional
Alguns fornecedores, como o Google (login e Gemini), a Anthropic e os serviços de tradução, podem tratar dados fora do Brasil. Nesses casos, a transferência ocorre para a execução do serviço solicitado por você e com fornecedores que adotam padrões de proteção compatíveis com a LGPD (art. 33).

## 6. Por quanto tempo guardamos
- **Dados da conta, alvos, varreduras e relatórios:** enquanto a conta existir. Ao excluir a conta, eles são removidos definitivamente.
- **Registros de acesso, tentativas de login e auditoria:** 6 (seis) meses, por obrigação legal (Marco Civil da Internet, art. 15), inclusive após a exclusão da conta. Após a exclusão, esses registros deixam de estar associados ao seu e-mail e à sua conta. Ao fim do prazo, são eliminados automaticamente.
- **Código enviado para análise:** não é armazenado pelo Checkop. O código enviado ao provedor de IA para a correção com IA (trecho ou arquivo inteiro) segue a política de retenção desse provedor (Anthropic ou Google) para uso da API. No registro de auditoria do Checkop fica só o nome do arquivo e a quantidade de achados, nunca o código.
- **Resumo das análises de código (histórico):** enquanto a conta existir ou até você apagá-lo na aba de análise de código. Ao excluir a conta, é removido definitivamente.
- **Conversas da Ajuda por IA:** não são guardadas pelo Checkop. O que é enviado ao provedor de IA segue a política de retenção desse provedor (Anthropic ou Google) para uso da API.

## 7. Cookies e armazenamento no navegador
- **Cookie de sessão (token):** essencial para manter você conectado. É protegido contra acesso por scripts (httpOnly), enviado apenas ao próprio Checkop (SameSite estrito) e expira em até 24 horas.
- **Armazenamento local:** guarda os dados básicos do usuário conectado, apenas para exibição na tela, e preferências de acessibilidade, como o alto contraste.
- **Armazenamento da sessão do navegador:** guarda rascunhos de formulários (por exemplo, o cadastro em andamento), sem senhas, apagados ao fechar a aba.
- No login com Google, o Google pode utilizar os seus próprios cookies, conforme a política de privacidade dele.

Não utilizamos cookies de publicidade nem de rastreamento de terceiros.

## 8. Segurança
Adotamos medidas técnicas e administrativas para proteger os dados, entre elas: senhas com hash criptográfico; sessão em cookie protegido e passível de revogação; comunicação criptografada (HTTPS) em produção; limitação de tentativas de login e de requisições; autenticação entre a plataforma e o motor de varredura; ocultação automática de dados sensíveis em resultados de produção; e controle de acesso para que cada usuário veja apenas os próprios dados.

Nenhum sistema é totalmente imune a incidentes. Caso ocorra um incidente de segurança que possa acarretar risco ou dano relevante, os titulares afetados e a Autoridade Nacional de Proteção de Dados (ANPD) serão comunicados, nos termos do art. 48 da LGPD.

## 9. Seus direitos
Nos termos do art. 18 da LGPD, você pode solicitar:
- confirmação da existência de tratamento e acesso aos seus dados;
- correção de dados incompletos, inexatos ou desatualizados;
- anonimização, bloqueio ou eliminação de dados desnecessários ou tratados em desconformidade com a lei;
- portabilidade dos dados a outro fornecedor;
- eliminação dos dados tratados com base no seu consentimento;
- informação sobre as entidades com as quais os dados são compartilhados;
- revisão de decisões tomadas unicamente com base em tratamento automatizado.

Diretamente na plataforma, em "Conta e privacidade", você pode:
- **baixar os seus dados** ("Baixar meus dados"): um arquivo JSON com a conta, o histórico de aceites dos Termos, os alvos, as varreduras com os achados, o resumo das análises de código, os acessos e os registros de auditoria, em formato que pode ser levado a outro serviço (acesso e portabilidade, art. 18, II e V). Ficam de fora apenas os segredos de autenticação (o hash da senha e os códigos de redefinição);
- consultar os acessos recentes à sua conta;
- excluir a conta definitivamente.

Os demais pedidos podem ser enviados para **privacidade@checkop.com.br** e serão respondidos em até 15 (quinze) dias, conforme o art. 19 da LGPD. Você também pode apresentar reclamação à ANPD.

## 10. Crianças e adolescentes
O Checkop não se destina a menores de 18 anos e não coleta intencionalmente dados de crianças e adolescentes.

## 11. Alterações desta Política
Esta Política pode ser atualizada para refletir mudanças na plataforma ou na legislação. A versão e a data da última atualização ficam indicadas no topo do documento, e alterações relevantes serão comunicadas na plataforma.

## 12. Contato
- Privacidade e dados pessoais: **privacidade@checkop.com.br**
- Assuntos gerais: **contato@checkop.com.br**
`.trim(),
};
