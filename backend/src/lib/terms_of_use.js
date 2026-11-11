// Termos de Uso do Checkop. A versão é a mesma gravada em TermsAcceptance.version
// (schema.prisma, padrão "1.0"): mudou o texto de forma relevante, suba a versão.
//
// RASCUNHO elaborado pela equipe do TCC. Antes de uso comercial, deve ser
// revisado por advogado.
export const TERMS_OF_USE = {
  version: '1.0',
  lastUpdated: '2026-11-09',
  content: `
# Termos de Uso — Checkop

## 1. Aceite
Ao criar uma conta ou usar o Checkop, você declara que leu e concorda com estes Termos e com a Política de Privacidade. Se não concordar, não utilize a plataforma.

## 2. O que é o Checkop
O Checkop é uma plataforma de análise de segurança que executa ferramentas de código aberto (OWASP ZAP, Nuclei, Subfinder e Semgrep) contra aplicações web e trechos de código indicados pelo próprio usuário, e apresenta os resultados em relatórios.

## 3. Uso permitido: somente sistemas seus ou autorizados
- Você só pode testar aplicações das quais é o responsável ou para as quais tem autorização expressa e por escrito do responsável.
- Testar sistemas de terceiros sem autorização pode configurar crime de invasão de dispositivo informático (art. 154-A do Código Penal, Lei 12.737/2012, com redação da Lei 14.155/2021).
- Para sites públicos, o Checkop exige a verificação de propriedade do domínio (registro DNS, arquivo ou meta tag). A verificação é conferida novamente antes de cada varredura.
- Ambientes locais (localhost e redes privadas) são tratados como ambiente de desenvolvimento e não exigem verificação; você continua responsável por ter autorização sobre eles.

## 4. Varredura ativa
- A varredura ativa envia requisições de ataque reais (por exemplo, tentativas de SQL Injection e XSS) para confirmar falhas.
- Em sites públicos, ela só é executada com a sua autorização expressa a cada execução, registrada com data, hora e endereço IP.
- Mesmo com velocidade reduzida, a varredura ativa pode gerar lentidão, registros de teste em formulários ou alertas em sistemas de monitoramento. Faça backup e, sempre que possível, prefira ambientes de homologação.
- Se a aplicação estiver em hospedagem compartilhada ou de terceiros, você declara que os termos do provedor permitem testes de segurança.

## 5. Condutas proibidas
- Testar, ou tentar testar, sistemas sem autorização, inclusive burlando a verificação de domínio.
- Usar a plataforma para ataques de negação de serviço, coleta de dados de terceiros ou qualquer fim ilícito.
- Tentar acessar a infraestrutura do próprio Checkop, contas de outros usuários ou o motor de varredura por fora da interface.
- Compartilhar sua conta ou suas credenciais.

## 6. Responsabilidades
- Você é o único responsável pelos alvos que cadastra, pelas autorizações que declara e pelo uso que faz dos resultados.
- O Checkop fornece as ferramentas e as salvaguardas técnicas descritas nestes Termos, mas não se responsabiliza por danos causados por uso em desacordo com eles ou por informações falsas prestadas pelo usuário.
- Os resultados são gerados por ferramentas automatizadas: podem conter falsos positivos e não garantem que uma aplicação esteja livre de falhas. Eles não substituem uma auditoria de segurança profissional.

## 7. Registros e cooperação com autoridades
- O Checkop registra ações relevantes (cadastro e verificação de domínios, criação e execução de varreduras, autorizações) e os acessos à conta, com data, hora e IP.
- Esses registros são guardados por 6 meses, em ambiente seguro, conforme o art. 15 do Marco Civil da Internet (Lei 12.965/2014), e podem ser fornecidos mediante ordem judicial.

## 8. Suspensão e encerramento
O Checkop pode suspender ou encerrar contas que violem estes Termos, especialmente em caso de indício de teste não autorizado. Você pode excluir sua conta a qualquer momento em "Conta e privacidade".

## 9. Planos
Os planos Free e Premium desta versão são demonstrativos e não envolvem cobrança.

## 10. Alterações
Estes Termos podem ser atualizados. Mudanças relevantes serão informadas na plataforma e poderão exigir novo aceite.

## 11. Legislação e foro
Estes Termos são regidos pelas leis brasileiras, incluindo a Lei Geral de Proteção de Dados (Lei 13.709/2018) e o Marco Civil da Internet.
`.trim(),
};
