// Termos de Uso do Checkop. A versão é a mesma gravada em TermsAcceptance.version
// (schema.prisma): mudou o texto de forma relevante, suba a versão.
//
// Texto elaborado pela equipe do TCC com base no Código Civil, no Código de
// Defesa do Consumidor, no Marco Civil da Internet, na LGPD e no art. 154-A do
// Código Penal. Antes de uso comercial, deve ser revisado por advogado.
//
// Formato: markdown simples lido por front-end/src/app/shared/ui/markdown.ts
// (#, ##, ###, listas com "-", destaque com "> " e negrito com **texto**).
export const TERMS_OF_USE = {
  version: '2.0',
  lastUpdated: '2026-11-16',
  content: `
# Termos de Uso

Estes Termos de Uso regulam o acesso e a utilização da plataforma Checkop. Leia com atenção: ao criar uma conta, inclusive pelo login com Google, ou ao utilizar qualquer funcionalidade, você declara que leu, compreendeu e concorda integralmente com estes Termos e com a Política de Privacidade, que é parte integrante deles.

> O Checkop executa testes de segurança reais. Utilize a plataforma somente em sistemas que são seus ou para os quais você tem autorização expressa do responsável. Testar sistemas de terceiros sem autorização pode configurar crime (art. 154-A do Código Penal).

## 1. Definições
- **Checkop ou Plataforma:** o serviço de análise de segurança de aplicações web e de código-fonte disponibilizado por meio do site e da API.
- **Usuário ou você:** a pessoa que cria uma conta e utiliza a Plataforma.
- **Alvo:** a aplicação, o domínio, o endereço ou o código indicado pelo Usuário para análise.
- **Varredura:** a execução das ferramentas de análise contra um Alvo.
- **Varredura passiva:** a análise que apenas observa as respostas do Alvo, sem enviar tentativas de ataque.
- **Varredura ativa:** a análise que envia requisições de ataque reais, como tentativas de injeção de SQL ou de scripts, para confirmar a existência de uma falha.
- **Verificação de propriedade:** a prova técnica, por registro DNS, arquivo ou meta tag, de que o Usuário controla o domínio ou o host do Alvo.
- **Relatório:** o conjunto de achados, evidências e recomendações gerado a partir de uma Varredura.

## 2. Sobre o Checkop
2.1. O Checkop é um projeto acadêmico, desenvolvido como Trabalho de Conclusão de Curso, que orquestra ferramentas de código aberto (OWASP ZAP, Nuclei, Subfinder, Semgrep e Gitleaks) e apresenta os resultados em relatórios adaptados ao perfil de cada Usuário.

2.2. A Plataforma é oferecida no estado em que se encontra, com as funcionalidades disponíveis em cada momento, e pode ser alterada, ampliada ou descontinuada, total ou parcialmente.

## 3. Cadastro e conta
3.1. Para utilizar a Plataforma, o Usuário deve ter pelo menos 18 anos e plena capacidade civil, ou agir em nome de pessoa jurídica com poderes para tanto.

3.2. O Usuário se compromete a fornecer informações verdadeiras e a mantê-las atualizadas. O cadastro pode ser feito com e-mail e senha ou com uma conta Google; neste caso, o nome, o e-mail e o identificador da conta são recebidos do Google.

3.3. A conta é pessoal e intransferível. O Usuário é responsável por manter a confidencialidade da senha e por todas as atividades realizadas na sua conta, devendo comunicar imediatamente qualquer uso não autorizado.

3.4. O perfil de uso (QA, Desenvolvedor, Pentester ou Estudante) define a forma de apresentação dos resultados e não altera os limites de uso destes Termos.

## 4. Planos
4.1. A Plataforma oferece os planos **Free** e **Premium**, cujos recursos e limites são apresentados na página de Planos. O plano **Enterprise** está em definição e não pode ser contratado nesta versão.

4.2. No plano Free, o Usuário pode realizar 1 (uma) varredura por dia, sempre do tipo básico (passiva), e visualizar a varredura mais recente, sem acesso à correção detalhada, à prova de conceito, ao painel de conformidade, ao histórico completo, à exportação de relatórios e à análise de código.

4.3. Nesta versão acadêmica, **os valores exibidos são demonstrativos e não há cobrança**: a troca entre os planos Free e Premium é gratuita e pode ser feita a qualquer momento na própria Plataforma. Caso venha a existir cobrança, as condições comerciais serão apresentadas previamente e dependerão de novo aceite.

## 5. Uso autorizado: somente alvos seus ou autorizados
5.1. O Usuário somente pode indicar como Alvo sistemas dos quais seja o responsável ou para os quais possua **autorização expressa e prévia** de quem é o responsável.

5.2. Antes de cada Varredura, o Usuário declara possuir essa autorização. A declaração é registrada com data, hora e endereço IP.

5.3. Para sites públicos, a Plataforma exige a Verificação de propriedade do domínio ou do host, conferida novamente antes de cada execução. Remover a prova de verificação suspende imediatamente a possibilidade de novas Varreduras.

5.4. Endereços locais e de redes privadas (como localhost) são tratados como ambiente de desenvolvimento e dispensam a Verificação de propriedade, sem afastar a responsabilidade do Usuário de possuir autorização sobre eles.

5.5. A Plataforma recusa automaticamente a execução de Varreduras em domínios públicos que resolvam para endereços de redes internas, mantendo o registro da tentativa para fins de auditoria.

## 6. Varredura ativa
6.1. Em sites públicos, a Varredura ativa somente é executada mediante autorização específica do Usuário a cada execução, na qual ele declara: (a) possuir autorização do responsável pelo Alvo; e (b) que os termos do provedor de hospedagem do Alvo permitem testes de segurança.

6.2. Em ambientes de produção, a Plataforma aplica limitação de velocidade e exclui modelos de teste reconhecidamente destrutivos ou de negação de serviço. Ainda assim, a Varredura ativa pode causar lentidão, gerar registros de teste em formulários, disparar alertas em sistemas de monitoramento ou alterar dados do Alvo.

6.3. Recomenda-se realizar backup antes de qualquer Varredura ativa e, sempre que possível, utilizar ambientes de homologação. A decisão de executar uma Varredura ativa e os seus efeitos sobre o Alvo são de responsabilidade do Usuário.

## 7. Análise de código
7.1. Ao enviar código-fonte para análise, o Usuário declara ter o direito de fazê-lo e se compromete a não enviar código de terceiros sem autorização.

7.2. O código enviado é processado apenas para gerar a análise e não é armazenado no banco de dados da Plataforma após a resposta. Evite enviar senhas, chaves ou dados pessoais reais; caso a análise encontre segredos no código, recomenda-se revogá-los.

7.3. A **correção com IA** é opcional e acionada pelo Usuário achado por achado: apenas as linhas em volta do achado são enviadas à Anthropic (modelo Claude) para gerar a sugestão. A sugestão é automática e pode conter erros; o Usuário deve revisá-la e testá-la antes de aplicá-la.

## 8. Condutas proibidas
É vedado ao Usuário:
- testar, ou tentar testar, sistemas sem autorização, inclusive burlando ou simulando a Verificação de propriedade;
- utilizar a Plataforma para ataques de negação de serviço, coleta não autorizada de dados, invasão, fraude ou qualquer finalidade ilícita;
- tentar acessar a infraestrutura do Checkop, as contas de outros usuários ou o motor de varredura por meios diversos da interface oferecida;
- realizar engenharia reversa, sobrecarregar intencionalmente a Plataforma ou contornar limites de uso e de plano;
- compartilhar a conta, revender o acesso ou utilizar os resultados para prejudicar terceiros;
- divulgar publicamente vulnerabilidades de sistemas de terceiros encontradas por meio da Plataforma sem observar práticas de divulgação responsável.

## 9. Resultados e limitações
9.1. Os resultados são produzidos por ferramentas automatizadas e podem conter falsos positivos e falsos negativos. A ausência de achados **não garante** que o Alvo esteja livre de vulnerabilidades.

9.2. As recomendações de correção e o mapeamento de conformidade (LGPD e PCI-DSS) têm caráter orientativo e **não substituem** uma auditoria de segurança, um parecer jurídico ou uma certificação oficial.

9.3. Em ambientes de produção, a Plataforma oculta automaticamente requisições, respostas e parâmetros sensíveis dos relatórios (Modo Seguro), para reduzir a exposição de dados reais.

## 10. Responsabilidades
10.1. O Usuário é o único responsável pelos Alvos que indica, pelas autorizações que declara, pela veracidade das informações prestadas e pelo uso que faz dos resultados.

10.2. O Usuário se compromete a indenizar o Checkop e a sua equipe por danos e despesas decorrentes do descumprimento destes Termos, em especial por testes realizados sem autorização.

10.3. Na máxima extensão permitida pela legislação aplicável, inclusive o Código de Defesa do Consumidor, o Checkop não responde por danos causados por uso em desacordo com estes Termos, por informações falsas prestadas pelo Usuário, por indisponibilidade temporária da Plataforma ou por decisões tomadas exclusivamente com base nos resultados automatizados.

## 11. Registros e cooperação com autoridades
11.1. A Plataforma registra ações relevantes (cadastro e verificação de alvos, criação e execução de varreduras, autorizações e trocas de plano) e os acessos à conta, com data, hora e endereço IP.

11.2. Esses registros são mantidos por 6 (seis) meses, em ambiente controlado e de acesso restrito, conforme o art. 15 do Marco Civil da Internet (Lei nº 12.965/2014), e somente serão fornecidos a terceiros mediante ordem judicial ou requisição de autoridade competente, nos termos da lei.

## 12. Propriedade intelectual
12.1. A marca, o código, o layout e os textos do Checkop pertencem aos seus autores. As ferramentas de código aberto utilizadas permanecem sujeitas às suas próprias licenças.

12.2. Os Alvos, o código enviado e os dados das Varreduras continuam pertencendo ao Usuário ou ao respectivo titular. O Checkop os utiliza apenas para prestar o serviço, conforme a Política de Privacidade.

## 13. Suspensão e encerramento
13.1. O Checkop pode suspender ou encerrar contas, sem aviso prévio, em caso de indício de teste não autorizado, de uso ilícito ou de descumprimento destes Termos, preservando os registros necessários para a apuração.

13.2. O Usuário pode excluir a sua conta a qualquer momento em "Conta e privacidade". A exclusão é definitiva e remove os alvos, as varreduras e os relatórios associados, observado o prazo legal de guarda dos registros de acesso descrito na Política de Privacidade.

## 14. Alterações destes Termos
Estes Termos podem ser atualizados para refletir mudanças na Plataforma ou na legislação. A versão e a data da última atualização ficam indicadas no topo do documento. Alterações relevantes serão comunicadas na Plataforma e poderão exigir novo aceite para a continuidade do uso.

## 15. Disposições gerais
15.1. Se alguma cláusula destes Termos for considerada inválida, as demais permanecem em vigor.

15.2. A tolerância quanto ao descumprimento de qualquer cláusula não significa renúncia ao direito de exigi-la.

15.3. Estes Termos são regidos pelas leis da República Federativa do Brasil. Fica eleito o foro do domicílio do Usuário para dirimir eventuais controvérsias, conforme o Código de Defesa do Consumidor.

## 16. Contato
Dúvidas sobre estes Termos podem ser enviadas para **contato@checkop.com.br**. Assuntos relacionados a dados pessoais devem ser tratados pelo canal indicado na Política de Privacidade.
`.trim(),
};
