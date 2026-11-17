// Política de Privacidade do Checkop (LGPD, Lei nº 13.709/2018).
// Descreve o que o sistema faz de fato; ao mudar coleta, compartilhamento ou
// retenção no código, atualize este texto e a data.
//
// Texto elaborado pela equipe do TCC. Antes de uso comercial, deve ser
// revisado por advogado. Contatos (e-mails) são provisórios.
//
// Formato: markdown simples lido por front-end/src/app/shared/ui/markdown.ts.
export const PRIVACY_POLICY = {
  version: '2.1',
  lastUpdated: '2026-11-17',
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

A correção com IA envia código à Anthropic, provedora do modelo de IA Claude, sempre e somente quando você pede:
- **"Gerar correção com IA"** (em um achado): envia só as linhas em volta daquele achado, não o arquivo inteiro.
- **"Corrigir o arquivo inteiro com IA"** (recurso pago com créditos de IA): envia o arquivo analisado inteiro e a lista de achados dele, para devolver o arquivo completo corrigido.

### 2.5. Dados sobre terceiros nos resultados
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
- **Anthropic (IA Claude):** somente quando você pede uma correção com IA na análise de código: as linhas em volta do achado ou, na correção completa, o arquivo analisado inteiro. Pelos termos comerciais da Anthropic, dados recebidos pela API não são usados, por padrão, para treinar os modelos dela.
- **Infraestrutura de hospedagem:** onde a plataforma e o banco de dados são executados.
- **Autoridades:** mediante ordem judicial ou requisição legal, nos limites da lei.

As ferramentas de análise (OWASP ZAP, Nuclei, Subfinder, Semgrep e Gitleaks) são executadas nos servidores do próprio Checkop.

## 5. Transferência internacional
Alguns fornecedores, como o Google, a Anthropic e os serviços de tradução, podem tratar dados fora do Brasil. Nesses casos, a transferência ocorre para a execução do serviço solicitado por você e com fornecedores que adotam padrões de proteção compatíveis com a LGPD (art. 33).

## 6. Por quanto tempo guardamos
- **Dados da conta, alvos, varreduras e relatórios:** enquanto a conta existir. Ao excluir a conta, eles são removidos definitivamente.
- **Registros de acesso, tentativas de login e auditoria:** 6 (seis) meses, por obrigação legal (Marco Civil da Internet, art. 15), inclusive após a exclusão da conta. Após a exclusão, esses registros deixam de estar associados ao seu e-mail e à sua conta. Ao fim do prazo, são eliminados automaticamente.
- **Código enviado para análise:** não é armazenado pelo Checkop. O código enviado à Anthropic para a correção com IA (trecho ou arquivo inteiro) segue a política de retenção da Anthropic para uso da API. No registro de auditoria do Checkop fica só o nome do arquivo e a quantidade de achados, nunca o código.

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

Diretamente na plataforma, em "Conta e privacidade", você pode consultar os acessos recentes à sua conta e excluí-la definitivamente. Os demais pedidos podem ser enviados para **privacidade@checkop.com.br** e serão respondidos em até 15 (quinze) dias, conforme o art. 19 da LGPD. Você também pode apresentar reclamação à ANPD.

## 10. Crianças e adolescentes
O Checkop não se destina a menores de 18 anos e não coleta intencionalmente dados de crianças e adolescentes.

## 11. Alterações desta Política
Esta Política pode ser atualizada para refletir mudanças na plataforma ou na legislação. A versão e a data da última atualização ficam indicadas no topo do documento, e alterações relevantes serão comunicadas na plataforma.

## 12. Contato
- Privacidade e dados pessoais: **privacidade@checkop.com.br**
- Assuntos gerais: **contato@checkop.com.br**
`.trim(),
};
