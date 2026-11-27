import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { PLAN_CARDS } from '../../shared/ui/plans';

interface SampleFinding {
  severity: 'Alto' | 'Médio';
  title: string;
  path: string;
}

@Component({
  selector: 'app-landing-page',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './landing-page.component.html',
  styleUrl: './landing-page.component.scss',
})
export class LandingPageComponent {
  // planos: shared/ui/plans.ts, os mesmos do cadastro
  protected readonly planCards = PLAN_CARDS;

  // prévia do produto no topo: achados reais do laboratório (backend/lab)
  protected readonly sampleFindings: SampleFinding[] = [
    { severity: 'Alto', title: 'Injeção de SQL', path: '/item?id=' },
    { severity: 'Alto', title: 'XSS refletido', path: '/search?q=' },
    { severity: 'Alto', title: 'Arquivo .env exposto', path: '/.env' },
    { severity: 'Médio', title: 'Redirecionamento aberto', path: '/redirect' },
    { severity: 'Médio', title: 'Formulário sem token anti-CSRF', path: '/conta' },
  ];

  // as etapas 2 e 3 (key) são o diferencial: só varre domínio comprovado e respeita o ambiente
  protected readonly steps = [
    { title: 'Você informa a URL', text: 'Entra na plataforma e diz qual site quer testar.', key: false },
    { title: 'Prova que o domínio é seu', text: 'Por registro DNS, arquivo ou meta tag, e aceita o termo de responsabilidade.', key: true },
    { title: 'O ambiente é identificado', text: 'Local, homologação ou produção. Em produção, só testes seguros.', key: true },
    { title: 'As ferramentas entram em ação', text: 'ZAP e Nuclei rodam o tipo de teste que você escolheu.', key: false },
    { title: 'Os achados são unificados', text: 'Um formato só, sem duplicatas, com nota CVSS e referência OWASP.', key: false },
    { title: 'Você recebe o relatório', text: 'Painel, histórico e exportação em PDF e JSON.', key: false },
  ];

  protected readonly tools = [
    { name: 'OWASP ZAP', text: 'Ataca o site como um invasor: XSS, SQL Injection, cabeçalhos.' },
    { name: 'Nuclei', text: 'Testa milhares de falhas conhecidas (CVEs) e configurações expostas.' },
    { name: 'Subfinder', text: 'Descobre os subdomínios do alvo.' },
    { name: 'Semgrep', text: 'Lê o código-fonte atrás de falhas de segurança.' },
    { name: 'Gitleaks', text: 'Acha senhas e chaves de API esquecidas no código.' },
    { name: 'OSV-Scanner', text: 'Aponta bibliotecas com vulnerabilidades conhecidas.' },
    { name: 'IA (Claude ou Gemini)', text: 'Sugere a correção do código vulnerável e tira dúvidas sobre os resultados, quando você pede.' },
    { name: 'DeepL', text: 'Traduz os achados das ferramentas para português.' },
  ];

  protected readonly audiences = [
    { name: 'QA', text: 'Evidência pronta para abrir o chamado: onde, como reproduzir e qual a gravidade.', icon: 'qa' },
    { name: 'Desenvolvedor', text: 'A linha do problema e a correção no código, antes de ir para produção.', icon: 'dev' },
    { name: 'Pentester', text: 'Payload usado, requisição crua e prova de conceito de cada achado.', icon: 'pentester' },
    { name: 'Estudante', text: 'Explicação de cada falha e referências da OWASP para aprender corrigindo.', icon: 'student' },
  ];
}
