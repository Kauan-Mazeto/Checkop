export const PRIVACY_POLICY = {
  lastUpdated: '2026-11-09',
  content: `
# Política de Privacidade — Checkop

## 1. Dados que coletamos
- Nome e e-mail, fornecidos no cadastro.
- Senha, armazenada apenas como hash (nunca em texto puro).
- URLs de alvos de varredura cadastrados por você, e os resultados dessas varreduras.
- Endereço IP e informações do navegador (user agent), registrados no cadastro, login e criação de varreduras, para fins de segurança e auditoria.
- Se você utilizar login via Google: nome, e-mail e um identificador único fornecido pelo Google.
- Alvos cadastrados (domínio ou host) e o resultado da verificação de propriedade.
- Registros de ações na plataforma (cadastro e verificação de alvos, criação e execução de varreduras, incluindo as declarações de autorização para varredura ativa), com data, hora e endereço IP.

## 2. Para que usamos esses dados
- Autenticar você e manter sua sessão ativa.
- Executar e exibir os resultados das varreduras de segurança solicitadas por você.
- Detectar e investigar tentativas de acesso indevido à sua conta.
- Comprovar que cada varredura foi autorizada por quem controla o alvo (art. 154-A do Código Penal).
- Cumprir obrigações legais e de segurança da informação, incluindo a guarda de registros de acesso a aplicações (Marco Civil da Internet, Lei 12.965/2014, art. 15).

## 3. Por quanto tempo guardamos
- Dados de conta: enquanto sua conta existir.
- Registros de acesso, de tentativas de login e de ações (auditoria): mantidos por 6 (seis) meses em ambiente controlado e sigiloso, inclusive após a exclusão da conta, por obrigação legal (Marco Civil da Internet, art. 15; LGPD, art. 16, I). Após a exclusão da conta, esses registros ficam dissociados do seu e-mail e do identificador da conta.

## 4. Seus direitos (LGPD)
- Solicitar a exclusão da sua conta e dos dados pessoais associados, a qualquer momento, através do recurso de exclusão de conta.
- Solicitar acesso aos dados que mantemos sobre você.

## 5. Contato
Em caso de dúvidas sobre esta política, entre em contato com a equipe responsável pelo Checkop.
`.trim(),
};

// Politica de privacidade, caso precise, se for usar no front, deixar aqui para futuras manutencoes