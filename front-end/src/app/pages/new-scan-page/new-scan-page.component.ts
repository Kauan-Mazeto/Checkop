import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { DraftService } from '../../core/services/draft.service';
import { ScanObjective, ScanService } from '../../core/services/scan.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { CheckComponent } from '../../shared/components/check/check.component';

export interface ObjectiveGroup {
  key: string;
  title: string;
  description: string;
  objectives: ScanObjective[];
}

// Agrupamento só de apresentação; a lista vem do backend (GET /api/scans/objectives).
const GROUPS: { key: string; title: string; description: string; members: string[] }[] = [
  {
    key: 'injection',
    title: 'Injeções',
    description: 'SQL, XSS, comandos, templates e arquivos do servidor',
    members: ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XXE', 'SSTI', 'CRLF_INJECTION'],
  },
  {
    key: 'requests',
    title: 'Requisições forjadas',
    description: 'CSRF, SSRF e redirecionamento aberto',
    members: ['OPEN_REDIRECT', 'CSRF', 'SSRF'],
  },
  {
    key: 'config',
    title: 'Configuração',
    description: 'Cabeçalhos, cookies, CORS, clickjacking e listagem',
    members: ['SECURITY_HEADERS', 'COOKIES', 'CLICKJACKING', 'CORS', 'DIRECTORY_LISTING'],
  },
  {
    key: 'exposure',
    title: 'Exposição de dados',
    description: 'Arquivos sensíveis, painéis, APIs e vazamentos',
    members: ['EXPOSED_FILES', 'ADMIN_PANELS', 'INFO_DISCLOSURE', 'API_EXPOSURE'],
  },
  {
    key: 'infra',
    title: 'Infraestrutura',
    description: 'CVEs, TLS/SSL, DNS e subdomínios',
    members: ['KNOWN_CVE', 'SSL_TLS', 'DNS_CHECK', 'SUBDOMAIN_ENUM'],
  },
  {
    key: 'full',
    title: 'Varredura completa',
    description: 'Tudo de uma vez (mais demorada)',
    members: ['FULL_SCAN'],
  },
];

export const groupObjectives = (objectives: ScanObjective[]): ObjectiveGroup[] => {
  const byKey = new Map(objectives.map((o) => [o.key, o]));
  const known = new Set(GROUPS.flatMap((g) => g.members));
  const groups = GROUPS.map((g) => ({
    key: g.key,
    title: g.title,
    description: g.description,
    objectives: g.members.map((m) => byKey.get(m)).filter((o): o is ScanObjective => Boolean(o)),
  }));
  const others = objectives.filter((o) => !known.has(o.key));
  if (others.length) groups.push({ key: 'other', title: 'Outros', description: '', objectives: others });
  return groups.filter((g) => g.objectives.length > 0);
};

const DRAFT_KEY = 'new-scan';

interface NewScanDraft {
  targetUrl: string;
  groupKey: string | null;
  objective: string | null;
}

@Component({
  selector: 'app-new-scan-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent, CheckComponent],
  templateUrl: './new-scan-page.component.html',
  styleUrl: './new-scan-page.component.scss',
})
export class NewScanPageComponent implements OnInit {
  private readonly scanService = inject(ScanService);
  private readonly drafts = inject(DraftService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected groups: ObjectiveGroup[] = [];
  private objectives: ScanObjective[] = [];
  protected isLoading = true;
  protected loadError: string | null = null;

  protected targetUrl = '';
  protected groupKey: string | null = null;
  protected objective: string | null = null;
  // a autorização nunca é lembrada: precisa ser dada de novo a cada varredura
  protected authorized = false;
  protected isSubmitting = false;
  protected submitError: string | null = null;
  protected needsVerification = false;

  ngOnInit(): void {
    const draft = this.drafts.load<NewScanDraft>(DRAFT_KEY);
    this.targetUrl = this.route.snapshot.queryParamMap.get('url') ?? draft.targetUrl ?? '';
    this.groupKey = draft.groupKey ?? null;
    this.objective = draft.objective ?? null;

    this.scanService.getObjectives().subscribe({
      next: (objectives) => {
        this.objectives = objectives;
        this.groups = groupObjectives(objectives);
        if (this.objective && !objectives.some((o) => o.key === this.objective)) this.objective = null;
        this.isLoading = false;
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.isLoading = false;
      },
    });
  }

  protected get activeGroup(): ObjectiveGroup | undefined {
    return this.groups.find((g) => g.key === this.groupKey);
  }

  protected get selected(): ScanObjective | undefined {
    return this.objectives.find((o) => o.key === this.objective);
  }

  protected get targetKind(): 'local' | 'public' | null {
    try {
      const { hostname } = new URL(this.targetUrl.trim());
      return hostname === 'localhost' || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname) ? 'local' : 'public';
    } catch {
      return null;
    }
  }

  protected chooseGroup(group: ObjectiveGroup): void {
    this.groupKey = group.key;
    // grupo com um único tipo (ex.: varredura completa) já vem selecionado
    if (group.objectives.length === 1) this.objective = group.objectives[0].key;
    else if (!group.objectives.some((o) => o.key === this.objective)) this.objective = null;
    this.saveDraft();
  }

  protected chooseObjective(key: string): void {
    this.objective = key;
    this.saveDraft();
  }

  protected saveDraft(): void {
    this.drafts.save<NewScanDraft>(DRAFT_KEY, { targetUrl: this.targetUrl, groupKey: this.groupKey, objective: this.objective });
  }

  protected get submitBlocker(): string | null {
    if (!this.targetKind) return 'Informe uma URL válida (com http:// ou https://).';
    if (!this.objective) return 'Escolha o tipo de falha.';
    if (!this.authorized) return 'Confirme a autorização para testar.';
    return null;
  }

  protected submit(): void {
    if (this.isSubmitting || this.submitBlocker) return;
    this.needsVerification = false;
    this.isSubmitting = true;
    this.submitError = null;

    this.scanService.createScan(this.targetUrl.trim(), this.objective!).subscribe({
      next: (scan) => {
        this.drafts.clear(DRAFT_KEY);
        this.router.navigate(['/scans', scan.id]);
      },
      error: (error: ApiError) => {
        this.isSubmitting = false;
        this.submitError = error.message;
        this.needsVerification = error.code === 'TARGET_NOT_VERIFIED';
      },
    });
  }
}
