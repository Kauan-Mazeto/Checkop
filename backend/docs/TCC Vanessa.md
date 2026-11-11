![][image1]

**COLÉGIO ESTADUAL LEONARDO DA VINCI — CURSO TÉCNICO EM DESENVOLVIMENTO DE SISTEMAS** 

Trabalho de Conclusão de Curso (TCC)

**Plataforma Integrada de Análise de Segurança para Aplicações Web \- Checkop**

 

Autores: 

MAZETO RODRIGUES, Kauan Gustavo

BARANCELLI, Luidi Augusto

Orientadora: 

SBARDELOTTO, Vanessa

Dois Vizinhos PR, 2026 

## **Lista de siglas**

* **API** – Application Programming Interface  
* **CI** – Continuous Integration (Integração Contínua)  
* **CVE** – Common Vulnerabilities and Exposures  
* **DAST** – Dynamic Application Security Testing  
* **DNS** – Domain Name System  
* **JWT** – JSON Web Token  
* **LGPD** – Lei Geral de Proteção de Dados Pessoais  
* **MVP** – Minimum Viable Product (Produto Mínimo Viável)  
* **OAuth** – Open Authorization  
* **ORM** – Object-Relational Mapping  
* **OWASP** – Open Worldwide Application Security Project  
* **QA** – Quality Assurance (Garantia de Qualidade)  
* **REST** – Representational State Transfer  
* **SAST** – Static Application Security Testing  
* **VPS** – Virtual Private Server  
* **ZAP** – Zed Attack Proxy

## 

## 

## 

## 

## 

## 

## 

## 

## 

## 

**Sumário**

1. **Título do projeto**  
2. **Introdução e justificativa**  
3. **Objetivo geral**  
4. **Objetivos específicos**  
5. **Referencial teórico e trabalhos relacionados**  
   * 5.1 Vulnerabilidades em aplicações web e o OWASP Top 10  
   * 5.2 Tipos de análise de segurança  
   * 5.3 Ferramentas de segurança utilizadas  
   * 5.4 Autenticação e autorização  
   * 5.5 Arquitetura modular  
   * 5.6 Soluções relacionadas  
6. **Escopo do sistema**  
   * 6.1 Público-alvo  
   * 6.2 Principais funcionalidades  
   * 6.3 Escopo negativo  
   * 6.4 Fluxo geral de uso  
7. **Tecnologias e arquitetura propostas**  
   * 7.1 Frontend  
   * 7.2 Backend  
   * 7.3 Banco de dados  
   * 7.4 Arquitetura  
   * 7.5 Infraestrutura e DevOps  
   * 7.6 Ferramentas de segurança do MVP  
8. **Metodologia**  
9. **Considerações éticas e legais**  
10. **Cronograma**  
11. **Estimativa de custos**  
12. **Riscos e mitigações**  
13. **Referências**

## 

## 

## 

## 

## **1\. Título do projeto**

**Checkop:** Plataforma Integrada de Análise de Segurança para Aplicações Web com Diferenciação de Perfil de Usuário e Ambiente de Execução.

## **2\. Introdução e justificativa**

A disponibilização de serviços por meio de aplicações web tornou-se parte central da rotina de empresas, órgãos públicos e usuários comuns, e essa presença constante amplia a superfície de ataque disponível a agentes mal-intencionados. Segundo o relatório Cost of a Data Breach, da IBM Security (2024), o custo médio global de uma violação de dados alcançou 4,88 milhões de dólares, valor que abrange tanto as perdas diretas quanto os danos de reputação, que costumam se prolongar por anos.

No Brasil, o cenário é agravado pela dificuldade de acesso a profissionais de segurança ofensiva. A formação desses especialistas é demorada, a oferta é limitada e a contratação costuma ser inviável para pequenas e médias empresas, que raramente mantêm uma equipe dedicada ao tema. O resultado é que muitas aplicações chegam à produção sem nenhuma avaliação de segurança, deixando dados de usuários expostos a falhas que poderiam ser identificadas por testes relativamente simples. Relatórios internacionais, como o Data Breach Investigations Report da Verizon (2024), incluem os ataques a aplicações web entre os padrões recorrentes de violação, e o CERT.br (s.d.) mantém estatísticas públicas dos incidentes reportados no país, o que reforça a relevância do problema também em âmbito nacional.

Do lado de quem precisa testar essas aplicações, a situação não é muito mais confortável. Desenvolvedores, analistas de qualidade (QA) e estudantes encontram, de um lado, serviços comerciais como o Pentest-Tools e o Pentester.com, que funcionam por assinatura e cuja combinação de custo e curva de aprendizado limita o uso por equipes pequenas e por quem ainda está em formação. De outro lado, existem ferramentas open source de alta qualidade, como o OWASP ZAP e o Nuclei, que são gratuitas, mas exigem instalação, configuração e conhecimento técnico para a interpretação de resultados brutos. Falta, portanto, uma opção intermediária, que reúna essas ferramentas em um único ambiente e apresente os achados de acordo com quem os lê e com o contexto em que a aplicação se encontra.

Como subsídio à definição do problema, foi realizada uma entrevista com Henrique Camargo, CEO da SUDOTEC – Centro de Desenvolvimento do Sudoeste Paranaense, em 26 de março de 2026, na qual foram discutidos aspectos relevantes do projeto (CAMARGO, 2026). A conversa contribuiu para situar a proposta diante da realidade do mercado regional de tecnologia, onde equipes enxutas de desenvolvimento precisam equilibrar prazos, custos e qualidade.

Diante desse cenário, propõe-se o desenvolvimento do Checkop, uma plataforma web modular que integra ferramentas open source consolidadas, adapta o nível de detalhamento dos resultados ao perfil do usuário e ao ambiente analisado e oferece uma interface acessível tanto a profissionais quanto a estudantes em formação técnica.

## **3\. Objetivo geral**

Desenvolver uma plataforma web modular, denominada Checkop, capaz de orquestrar as ferramentas open source de análise de segurança OWASP ZAP e Nuclei e de apresentar os resultados de forma adaptada ao perfil do usuário (desenvolvedor, analista de QA, pentester ou estudante) e ao ambiente da aplicação analisada (desenvolvimento ou homologação, e produção), com o propósito de ampliar o acesso a práticas de teste de segurança e contribuir para a redução de vulnerabilidades em aplicações web.

## **4\. Objetivos específicos**

Para alcançar o objetivo geral, o trabalho se divide nos seguintes objetivos específicos:

1. Levantar e analisar os requisitos funcionais e não funcionais do sistema, por meio de pesquisa bibliográfica, análise de ferramentas concorrentes e da entrevista realizada, considerando os quatro perfis de usuário (DEV, QA, Pentester e Estudante). Este objetivo será considerado cumprido com a entrega de um documento de requisitos contendo ao menos quinze requisitos priorizados.  
2. Modelar a arquitetura e o banco de dados, elaborando os diagramas de casos de uso, de entidade-relacionamento e de fluxo de dados, além do esquema relacional que armazenará usuários, alvos, varreduras e resultados. Os diagramas serão validados com a orientadora antes do início da codificação.  
3. Desenvolver o módulo de orquestração (VulnFlow Engine), responsável por se comunicar com o OWASP ZAP, por meio de sua API REST, e com o Nuclei, por meio de linha de comando, identificar o ambiente da aplicação-alvo e filtrar as respostas conforme o perfil do usuário. O critério de conclusão é a execução de varreduras completas nas duas ferramentas, com os resultados normalizados em um formato único.  
4. Desenvolver o frontend e o sistema de autenticação, com interfaces diferenciadas por perfil, cadastro, login, recuperação de senha e autenticação OAuth 2.0 com Google, assegurando responsividade e acessibilidade. Espera-se que os quatro perfis estejam funcionais e que a navegação ocorra sem erros críticos nos principais navegadores.  
5. Implementar os mecanismos de uso responsável da plataforma, que incluem a verificação de propriedade do domínio, o termo de responsabilidade e o registro de auditoria, descritos na seção 9\. Nenhuma varredura deverá ser executada contra um alvo que não tenha sido verificado.  
6. Testar e documentar o sistema, por meio de testes funcionais, de integração e de segurança sobre a própria plataforma, da avaliação em ambiente controlado com aplicações intencionalmente vulneráveis (DVWA e OWASP Juice Shop) e da documentação técnica da API e dos fluxos de uso.

A avaliação do trabalho terá como referência as seguintes metas: detectar ao menos 70% das vulnerabilidades de um subconjunto previamente definido do Juice Shop e do DVWA, escolhido entre categorias do OWASP Top 10 como injeção, quebra de controle de acesso e configuração insegura; concluir uma varredura básica em aplicação de pequeno porte em até quinze minutos; atingir cobertura de testes automatizados de pelo menos 60% nos módulos de orquestração e de filtragem por perfil; e garantir que, no Modo Seguro, nenhum dado sensível, como corpos de resposta, credenciais ou payloads completos, seja exibido ao usuário.

## **5\. Referencial teórico e trabalhos relacionados**

### **5.1 Vulnerabilidades em aplicações web e o OWASP Top 10**

O OWASP Top 10 é um documento de consenso, elaborado pela comunidade da OWASP Foundation, que reúne as categorias de risco mais críticas em aplicações web, como controle de acesso quebrado, falhas criptográficas e injeção (OWASP FOUNDATION, 2021). Por ser amplamente adotado como referência pela indústria, ele orienta tanto a escolha do que as varreduras do Checkop devem cobrir quanto a forma de classificar e nomear os achados apresentados ao usuário.

### **5.2 Tipos de análise de segurança**

A análise dinâmica (DAST) examina a aplicação em execução, enviando requisições e observando o comportamento das respostas, e é o foco do MVP por meio do OWASP ZAP e do Nuclei. A análise estática (SAST), por sua vez, inspeciona o código-fonte sem executá-lo e fica reservada para versões futuras da plataforma. Quanto ao grau de intrusão, a varredura passiva limita-se a observar o tráfego e as respostas, sem alterar o comportamento da aplicação, enquanto a varredura ativa envia requisições manipuladas para provocar falhas. Por ser mais invasiva, a varredura ativa exige autorização expressa do responsável pelo sistema e cuidado redobrado quando executada em produção.

### **5.3 Ferramentas de segurança utilizadas**

O OWASP ZAP é um scanner de segurança web de código aberto, mantido pela comunidade OWASP, que dispõe de uma API REST capaz de controlar varreduras de forma programática (OWASP FOUNDATION, s.d.). O Nuclei, desenvolvido pela ProjectDiscovery, executa templates escritos em YAML e mantidos pela comunidade para detectar vulnerabilidades conhecidas, configurações inseguras e exposições de dados (PROJECTDISCOVERY, s.d.). As duas ferramentas se complementam: o ZAP é mais indicado para a exploração ampla de uma aplicação, ao passo que o Nuclei é eficiente na verificação de problemas já catalogados.

### **5.4 Autenticação e autorização**

O projeto adota o JSON Web Token (JWT) para manter sessões sem estado em uma API REST, conforme descrito na RFC 7519 (IETF, 2015), e o protocolo OAuth 2.0 para permitir o login por meio de um provedor externo, no caso o Google, nos termos da RFC 6749 (IETF, 2012). Essa combinação dispensa o armazenamento de sessões no servidor e reduz a necessidade de o sistema guardar senhas de usuários que optem pelo login social.

### **5.5 Arquitetura modular**

O sistema adota uma arquitetura modular em camadas, na qual a API, o módulo de orquestração e o banco de dados têm responsabilidades separadas. Essa organização favorece a manutenção por uma equipe pequena, facilita os testes de cada parte isoladamente e permite que, em trabalhos futuros, algum módulo seja extraído como serviço independente, caso a demanda justifique.

### **5.6 Soluções relacionadas**

Entre as soluções comerciais, o Pentest-Tools (s.d.) e o Pentester.com (s.d.) oferecem varreduras em nuvem por meio de uma interface web, em modelo de assinatura. O ZAP e o Nuclei, quando usados isoladamente, dispensam custo de licença, mas o primeiro exige instalação e configuração próprias e o segundo opera apenas por linha de comando. Na análise preliminar dessas alternativas, não se identificou como foco central nem a adaptação do conteúdo dos relatórios ao perfil de quem os consulta, nem a aplicação de políticas distintas conforme o ambiente da aplicação seja de desenvolvimento ou de produção. É nessa lacuna que o Checkop se posiciona: gratuito e de código aberto, integra duas ferramentas consolidadas em uma única interface, ajusta o nível de detalhe dos resultados ao usuário e ao ambiente e dá atenção específica ao uso educacional.

## **6\. Escopo do sistema**

### **6.1 Público-alvo**

O sistema foi pensado para quatro perfis. Os desenvolvedores web (DEV) precisam validar a segurança de suas aplicações durante o desenvolvimento, sem necessariamente dominar a segurança ofensiva. Os analistas de QA buscam incorporar verificações de segurança aos testes funcionais e não funcionais que já realizam. Os pentesters e caçadores de recompensas por bugs (Bug Bounty) necessitam de logs técnicos, payloads e resultados brutos das ferramentas. Já os estudantes de tecnologia querem compreender, de forma didática, como as vulnerabilidades funcionam e como se defender delas.

### **6.2 Principais funcionalidades**

* Autenticação por e-mail e senha e por OAuth 2.0 (Google), com recuperação de senha.  
* Verificação de propriedade do alvo antes de qualquer varredura, conforme a seção 9\.  
* Módulo de identificação de ambiente, que detecta se a URL-alvo é local (localhost), de homologação (staging) ou de produção, para aplicar a política de resposta correspondente.  
* Modo Verboso (Verbose Mode), voltado a ambientes de desenvolvimento e homologação, com detalhes técnicos completos, rastreamento de pilha de erros e dados sem mascaramento.  
* Modo Seguro (Safe Mode), voltado a ambientes de produção, com filtragem de dados sensíveis e exibição restrita a cabeçalhos HTTP, códigos de resposta e classificação do tipo de vulnerabilidade encontrada.  
* Integração com o OWASP ZAP, para varreduras ativas e passivas, e com o Nuclei, para execução de templates de detecção de vulnerabilidades conhecidas.  
* Dashboard diferenciado por perfil: interface simplificada com gráficos e exportação de relatórios para QA; alertas automatizados e modo debug para DEV; logs técnicos e payloads completos para Pentester; e painel educacional com explicações contextualizadas para Estudante.  
* Geração e exportação de relatórios nos formatos PDF e JSON.  
* Histórico de análises por usuário, com persistência em banco de dados.

### **6.3 Escopo negativo**

Para garantir a viabilidade do desenvolvimento dentro do prazo do TCC, ficam explicitamente fora do MVP, podendo ser objeto de trabalhos futuros: a integração com Nmap e Semgrep; a análise de código-fonte de repositórios externos por meio de plataformas de versionamento como GitHub e GitLab; um sistema de assinatura e cobrança, em modelo freemium ou SaaS comercial; e o suporte a aplicativos móveis (Android e iOS).

### **6.4 Fluxo geral de uso**

O funcionamento esperado da plataforma segue as etapas abaixo:

1. O usuário se autentica e informa a URL da aplicação a ser analisada.  
2. O sistema verifica a propriedade do domínio e o aceite do termo de responsabilidade.  
3. O módulo de identificação classifica o ambiente como local, de homologação ou de produção.  
4. O VulnFlow Engine executa as varreduras permitidas pela política daquele ambiente, com o ZAP, o Nuclei ou ambos.  
5. Os resultados são normalizados em um formato único.  
6. O filtro de perfil e de ambiente define o que será exibido, em Modo Verboso ou em Modo Seguro.  
7. O relatório é apresentado no dashboard, pode ser exportado e fica registrado no histórico do usuário.

## 

## **7\. Tecnologias e arquitetura propostas**

A escolha das tecnologias seguiu três critérios: a viabilidade de aprendizado e implementação por alunos de nível técnico dentro do prazo disponível, a presença consolidada no mercado de desenvolvimento web e a compatibilidade entre os componentes da stack.

### **7.1 Frontend**

O frontend será desenvolvido em Angular, na versão 17 ou superior, framework baseado em TypeScript escolhido pela afinidade prévia da equipe e pela estrutura opinativa, que impõe organização ao código desde o início, vantagem relevante em um projeto com mais de um colaborador. A biblioteca Angular Material fornecerá os componentes de interface, como tabelas, formulários e navegação, o que reduz o esforço de estilização. O gerenciamento de estado será feito com Signals, recurso nativo do Angular que exige menos código repetitivo que o NgRx e se adequa ao porte do projeto. Para os gráficos dos dashboards, será utilizada a biblioteca Chart.js, integrada ao Angular por meio do ng2-charts.

### **7.2 Backend**

O backend será construído com Node.js e Express.js, em TypeScript, para a criação da API RESTful. O uso de TypeScript mantém a tipagem compartilhada com o frontend e aproveita os tipos gerados automaticamente pelo Prisma. A autenticação será feita com JWT e Passport.js, incluindo a estratégia OAuth 2.0 para o login com Google.

A execução das ferramentas de segurança ficará a cargo de workers escritos em Python, que controlam o OWASP ZAP por sua API REST e o Nuclei por linha de comando. A escolha de uma segunda linguagem justifica-se pelo ecossistema maduro de automação de segurança em Python, inclusive com biblioteca oficial para o ZAP, e pelo isolamento das ferramentas externas em um módulo próprio, que pode falhar ou ser reiniciado sem derrubar a API. A comunicação entre a API e os workers ocorrerá por meio de uma fila de tarefas.

### **7.3 Banco de dados**

O PostgreSQL foi escolhido como sistema gerenciador de banco de dados por ser robusto, de código aberto e oferecer suporte nativo a JSON, recurso útil para armazenar os resultados brutos das ferramentas. O acesso será intermediado pelo Prisma ORM, que abstrai a comunicação com o banco, gera tipos TypeScript e reduz a chance de erros em consultas SQL escritas manualmente.

### **7.4 Arquitetura**

A arquitetura adotada é a de um monólito modular com workers assíncronos, e não a de microsserviços. A decisão considera que o projeto é desenvolvido por duas pessoas: microsserviços aumentariam a complexidade de implantação, comunicação e monitoramento sem trazer benefício proporcional. Os módulos de autenticação, identificação de ambiente, orquestração, filtragem por perfil e relatórios terão fronteiras bem definidas, de modo que possam ser separados em serviços independentes no futuro.

### **7.5 Infraestrutura e DevOps**

O Backend, o banco de dados e a instância do ZAP serão hospedados em uma VPS da Hostinger, solução de custo acessível e compatível com as restrições orçamentárias do projeto. Como o ZAP é executado em Java e demanda memória considerável, a configuração do servidor deverá oferecer ao menos 2 GB de RAM, e o ZAP poderá ser executado em contêiner na máquina local durante o desenvolvimento. A integração contínua será feita com GitHub Actions, que executará os testes automatizados a cada commit e ajudará a manter a estabilidade do código.

### **7.6 Ferramentas de segurança do MVP**

O núcleo do MVP é formado pelo OWASP ZAP, que cobre as vulnerabilidades do OWASP Top 10 e dispõe de API REST para integração programática, e pelo Nuclei, que utiliza templates YAML e um repositório público de templates para detectar CVEs, configurações inseguras e exposições de dados. A integração com o Nuclei será feita por subprocesso em Python, procedimento direto e bem documentado.

## **8\. Metodologia**

Trata-se de uma pesquisa aplicada, de caráter tecnológico, cujo resultado é um produto de software. A fase de requisitos combina levantamento bibliográfico e documental com a entrevista realizada, e a validação final adota abordagem predominantemente qualitativa, complementada por métricas quantitativas obtidas nos testes.

O desenvolvimento seguirá um modelo incremental e iterativo, com práticas do Scrum adaptadas a uma equipe de duas pessoas: sprints de duas semanas, backlog priorizado pelo método MoSCoW e revisão das entregas com a orientadora ao final de cada ciclo. As tarefas serão acompanhadas em um quadro Kanban, e o código será versionado em Git, com revisão cruzada entre os autores.

As responsabilidades serão divididas de forma colaborativa. Cada autor assumirá a responsabilidade principal por um conjunto de módulos, de um lado a orquestração e as integrações com o ZAP e o Nuclei, de outro a interface e a autenticação, enquanto a modelagem do banco de dados, os testes e a documentação serão compartilhados. A revisão cruzada evita que algum conhecimento fique concentrado em uma única pessoa.

A validação ocorrerá em três níveis. O primeiro é o dos testes unitários e de integração automatizados, executados na integração contínua. O segundo é o dos testes de segurança sobre a própria plataforma, que verificam, por exemplo, falhas do OWASP Top 10 na API e no fluxo de autenticação. O terceiro é o da avaliação em ambiente controlado, com varreduras contra o DVWA e o OWASP Juice Shop executados em contêineres locais, comparando os achados do Checkop com as vulnerabilidades documentadas dessas aplicações e confrontando os resultados com as metas definidas na seção 4\.

## **9\. Considerações éticas e legais**

Por ser uma ferramenta de análise de segurança, o Checkop pode ser usado de forma indevida, e por isso o projeto incorpora salvaguardas desde a concepção.

A primeira delas é a verificação de propriedade do alvo. Antes da primeira varredura, o usuário deverá comprovar o controle sobre o domínio por meio de um registro DNS do tipo TXT, de um arquivo publicado em caminho definido ou de uma meta tag na página inicial. Alvos de localhost e de redes privadas serão tratados como ambiente de desenvolvimento. Soma-se a isso um termo de responsabilidade, no qual o usuário declara ter autorização para testar o alvo e assume a responsabilidade pelo uso da plataforma, com registro de data, hora e identificação no banco de dados.

As varreduras também seguem uma política por ambiente. Em produção, o Modo Seguro limita a exposição de dados e, por padrão, restringe a execução a varreduras de baixo impacto, como as passivas e as baseadas em templates não destrutivos, exigindo confirmação explícita para varreduras ativas. Há ainda limite de varreduras por usuário e por período, e todas as execuções ficam registradas em log de auditoria.

Quanto à proteção de dados, serão coletados apenas os dados pessoais necessários ao funcionamento do sistema, como nome, e-mail e histórico de uso, com finalidade informada, armazenamento seguro das senhas por meio de hash e possibilidade de exclusão da conta, em conformidade com a Lei nº 13.709/2018 (LGPD). Os resultados das varreduras, que podem conter informações sensíveis dos sistemas analisados, serão acessíveis somente ao usuário que os gerou.

No plano legal, destacam-se a Lei nº 12.737/2012, que tipifica a invasão de dispositivo informático, e a Lei nº 12.965/2014, o Marco Civil da Internet. A documentação da plataforma deixará claro que o uso é permitido apenas mediante autorização do titular do sistema analisado. Por fim, todos os testes realizados no âmbito deste trabalho ocorrerão em aplicações próprias ou intencionalmente vulneráveis, como o DVWA e o Juice Shop, nunca contra sistemas de terceiros.

## **10\. Cronograma**

O projeto está planejado para oito meses, distribuídos em fases que se sobrepõem parcialmente. Os dois primeiros meses são dedicados ao levantamento de requisitos e ao referencial teórico, e a modelagem da arquitetura, dos diagramas e do banco de dados ocupa o segundo e o terceiro meses. A autenticação e a API base são desenvolvidas entre o terceiro e o quarto mês, e o VulnFlow Engine, com as integrações com o ZAP e o Nuclei, a identificação de ambiente e o filtro por perfil, entre o quarto e o quinto.

O frontend e os dashboards por perfil são construídos entre o quinto e o sexto mês, período em que também são implementados os mecanismos de uso responsável. Os testes funcionais, de integração e de segurança ocorrem entre o sexto e o sétimo mês, e a avaliação em DVWA e Juice Shop, com os ajustes decorrentes, no sétimo. A documentação técnica e a redação final acompanham o trabalho do sexto ao oitavo mês, e o oitavo mês é reservado para a entrega e a defesa.

Quatro marcos orientam o acompanhamento: a aprovação dos requisitos e da modelagem, ao final do terceiro mês; a primeira varredura executada de ponta a ponta, ao final do quinto; o MVP funcional com os quatro perfis, ao final do sexto; e a conclusão da avaliação e da documentação final, ao final do oitavo.

## **11\. Estimativa de custos**

Os valores a seguir são aproximados e poderão ser revistos ao longo do desenvolvimento.

* Servidor VPS (Hostinger), para hospedagem do backend, do banco de dados e da instância do ZAP: R\$ 360,00 por ano.  
* Registro do domínio checkop.com.br, via Registro.br: R\$ 80,00 por ano.  
* Plano de internet para a equipe durante o desenvolvimento: R\$ 1060,00 por ano.  
* Equipamento para desenvolvimento e testes: R\$ 20.500,00, em custo único ( tempo de serviço dos desenvolvedores ).  
* Ferramentas e bibliotecas, todas open source e sem custo de licença: R\$ 0,00.

O subtotal é de R\$ 23.500,00. Como o ZAP exige memória considerável, o plano básico de VPS, de cerca de R\$ 30,00 por mês, pode se mostrar insuficiente, e uma eventual migração para um plano com mais recursos, assim como outros imprevistos, será coberta por uma reserva de contingência de 10%, equivalente a R\$ 426,00. O custo total estimado para o primeiro ano é, portanto, de R\$ 4.686,00. Não foi contabilizado o valor das horas de trabalho dos autores.

## **12\. Riscos e mitigações**

O principal risco do projeto é o prazo. Duas pessoas dispõem de tempo limitado para construir uma plataforma com autenticação, orquestração, interfaces por perfil e mecanismos de proteção, e é por isso que o escopo negativo foi definido de forma explícita, a priorização segue o método MoSCoW e o MVP se restringe ao ZAP e ao Nuclei.

O segundo risco é o uso da plataforma contra alvos sem autorização. Ele é tratado com a verificação de domínio, o termo de responsabilidade, o limite de varreduras e o log de auditoria descritos na seção 9\.

Há também riscos técnicos. O consumo de memória do ZAP pode exceder o que o plano da VPS oferece, e a mitigação é optar por um plano com mais RAM, executar o ZAP localmente durante o desenvolvimento e limitar o número de varreduras simultâneas. A integração entre a API em Node.js e os workers em Python pode apresentar dificuldades, e por isso será feita uma prova de conceito logo no início da etapa de orquestração, com uma interface simples baseada em fila. Por fim, a própria plataforma pode conter vulnerabilidades, o que será tratado com testes de segurança sobre o sistema, revisão cruzada do código e atualização constante das dependências.

Quanto à equipe, a indisponibilidade de um integrante ou a sobrecarga de tarefas são mitigadas pela divisão clara de responsabilidades e pela revisão cruzada, que evitam a dependência de uma só pessoa.

## **Referências**

BRASIL. **Lei nº 12.737, de 30 de novembro de 2012**. Dispõe sobre a tipificação criminal de delitos informáticos. Brasília, DF, 2012\.

BRASIL. **Lei nº 12.965, de 23 de abril de 2014**. Estabelece princípios, garantias, direitos e deveres para o uso da Internet no Brasil (Marco Civil da Internet). Brasília, DF, 2014\.

BRASIL. **Lei nº 13.709, de 14 de agosto de 2018**. Lei Geral de Proteção de Dados Pessoais (LGPD). Brasília, DF, 2018\.

CAMARGO, Henrique. **Entrevista** (depoimento oral). CEO da SUDOTEC – Centro de Desenvolvimento do Sudoeste Paranaense. Dois Vizinhos, 26 mar. 2026\.

CERT.BR. **Estatísticas dos incidentes reportados ao CERT.br**. Disponível em: https\://www\.cert.br/stats/incidentes/. Acesso em: 8 nov. 2026\.

IBM SECURITY. **Cost of a Data Breach Report 2024**. Armonk: IBM, 2024\. Disponível em: https\://www\.ibm.com/reports/data-breach. Acesso em: 8 nov. 2026\.

IETF. **RFC 6749: The OAuth 2.0 Authorization Framework**. 2012\. Disponível em: https\://datatracker.ietf.org/doc/html/rfc6749. Acesso em: 8 nov. 2026\.

IETF. **RFC 7519: JSON Web Token (JWT)**. 2015\. Disponível em: https\://datatracker.ietf.org/doc/html/rfc7519. Acesso em: 8 nov. 2026\.

OWASP FOUNDATION. **OWASP Top Ten**. 2021\. Disponível em: https\://owasp.org/www-project-top-ten/. Acesso em: 8 nov. 2026\.

OWASP FOUNDATION. **OWASP Zed Attack Proxy (ZAP)**. \[s.d.\]. Disponível em: https\://www\.zaproxy.org/. Acesso em: 8 nov. 2026\.

PENTEST-TOOLS. **Pentest-Tools.com**. \[s.d.\]. Disponível em: https\://pentest-tools.com/. Acesso em: 8 nov. 2026\.

PENTESTER.COM. **Pentester.com**. \[s.d.\]. Disponível em: https\://pentester.com/. Acesso em: 8 nov. 2026\.

PROJECTDISCOVERY. **Nuclei: fast and customizable vulnerability scanner**. \[s.d.\]. Disponível em: https\://github.com/projectdiscovery/nuclei. Acesso em: 8 nov. 2026\.

VERIZON. **2024 Data Breach Investigations Report**. Nova York: Verizon, 2024\. Disponível em: https\://www\.verizon.com/business/resources/reports/dbir/. Acesso em: 8 nov. 2026\.