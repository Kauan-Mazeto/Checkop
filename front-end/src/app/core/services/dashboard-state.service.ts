import { DOCUMENT } from '@angular/common';
import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  EMPTY,
  Observable,
  Subscription,
  catchError,
  forkJoin,
  map,
  of,
  switchMap,
  tap,
  timer,
} from 'rxjs';
import {
  PLAN_DEFINITIONS,
  ROLE_PANEL,
  SCAN_POLL_INTERVAL_MS,
} from '../constants/dashboard.constants';
import { AuthUser, UserRole } from './auth.service';
import { PlanService } from './plan.service';
import { Finding, Scan, ScanObjective, ScanService } from './scan.service';

// Resultado de "iniciar scan": o scan SEMPRE é registrado primeiro; se a
// execução falhar (limite de requisições, motor de segurança fora do ar...),
// `runError` traz o motivo e o scan continua PENDING no histórico, com o
// botão "Executar" disponível.
export interface StartScanOutcome {
  scan: Scan;
  runError: string | null;
}

// Estado compartilhado pelos componentes do dashboard. NÃO é providedIn: 'root'
// — é declarado em `providers` do DashboardPageComponent, então nasce e morre
// junto com a página (sair do dashboard descarta scans/findings em memória e
// para o acompanhamento de scans em execução).
//
// Tudo que o backend alimenta passa por aqui: user/role (auth), scans
// (GET /api/scans), findings (GET /api/scans/:id) e execução
// (POST /api/scans/:id/run). Os componentes só leem e chamam estes métodos.
@Injectable()
export class DashboardStateService {
  private readonly scanService = inject(ScanService);
  private readonly planService = inject(PlanService);
  private readonly document = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);

  private pollSubscription: Subscription | null = null;

  // ---------- sessão ----------
  readonly user = signal<AuthUser | null>(null);

  // O perfil é sempre o real, vindo do backend (GET /api/auth/me).
  readonly role = computed<UserRole>(() => this.user()?.role ?? 'STUDENT');
  readonly rolePanel = computed(() => ROLE_PANEL[this.role()]);

  // ---------- plano ----------
  readonly plan = this.planService.plan;
  readonly planDefinition = computed(() => PLAN_DEFINITIONS[this.plan()]);

  // ---------- dados do backend ----------
  readonly scans = signal<Scan[]>([]);
  readonly isLoadingScans = signal(true);
  readonly scansError = signal<string | null>(null);

  readonly findings = signal<Finding[]>([]);
  readonly findingsError = signal<string | null>(null);

  // ---------- UI ----------
  readonly highContrast = signal(false);
  // incrementa a cada clique em "+ Novo scan"; o ScanPanel observa e foca o campo
  readonly scanFocusRequest = signal(0);

  // ---------- métricas (calculadas a partir dos scans reais) ----------
  readonly totalScans = computed(() => this.scans().length);
  readonly completedScans = computed(
    () => this.scans().filter((scan) => scan.status === 'COMPLETED').length
  );
  readonly runningScans = computed(
    () => this.scans().filter((scan) => scan.status === 'RUNNING').length
  );
  readonly suspiciousScans = computed(
    () => this.scans().filter((scan) => scan.suspiciousEnvironment).length
  );
  readonly flaggedScans = computed(() =>
    this.scans()
      .filter((scan) => scan.status === 'FAILED' || scan.suspiciousEnvironment)
      .slice(0, 5)
  );

  readonly latestCompletedScan = computed(
    () => this.scans().find((scan) => scan.status === 'COMPLETED') ?? null
  );

  // scans criados hoje (dia do calendário local do usuário)
  readonly scansToday = computed(() => {
    const now = new Date();
    return this.scans().filter((scan) => {
      const createdAt = new Date(scan.createdAt);
      return (
        createdAt.getFullYear() === now.getFullYear() &&
        createdAt.getMonth() === now.getMonth() &&
        createdAt.getDate() === now.getDate()
      );
    }).length;
  });

  // null = ilimitado (Premium). No Free, 1 scan por dia.
  readonly scansRemaining = computed<number | null>(() => {
    const limit = this.planDefinition().dailyScanLimit;
    return limit === null ? null : Math.max(limit - this.scansToday(), 0);
  });

  // ---------- carregamento ----------
  loadScans(): void {
    this.isLoadingScans.set(true);
    this.scansError.set(null);

    this.scanService.listScans().subscribe({
      next: (scans) => {
        this.scans.set(scans);
        this.isLoadingScans.set(false);
        this.loadFindings(scans);
        // a página pode abrir com um scan que já estava rodando
        this.ensurePolling();
      },
      error: (message: string) => {
        this.scansError.set(message);
        this.isLoadingScans.set(false);
      },
    });
  }

  // O backend não tem um endpoint que liste findings de todos os scans, só
  // GET /api/scans/:id. Então buscamos os findings dos 5 scans concluídos mais
  // recentes. Os painéis QA/Dev/Pentester/Estudante leem `findings`.
  // BACKEND: se isso pesar, criar GET /api/findings (agregado) e usar aqui.
  private loadFindings(scans: Scan[]): void {
    this.findingsError.set(null);
    const recentCompleted = scans.filter((scan) => scan.status === 'COMPLETED').slice(0, 5);

    if (recentCompleted.length === 0) {
      this.findings.set([]);
      return;
    }

    forkJoin(recentCompleted.map((scan) => this.scanService.getScan(scan.id))).subscribe({
      next: (details) => this.findings.set(details.flatMap((detail) => detail.findings)),
      error: (message: string) => this.findingsError.set(message),
    });
  }

  // ---------- criar e executar scans ----------

  // Registra o scan e já dispara a execução. Se só a execução falhar, o scan
  // fica salvo (PENDING) e o motivo volta em `runError`.
  // O objetivo é decidido pelo PLANO: no Free (canChooseObjective = false) vale
  // sempre o scan básico, mesmo que alguém tente passar outro. O servidor
  // também precisa impor essa regra.
  startScan(targetUrl: string, objective?: ScanObjective): Observable<StartScanOutcome> {
    const plan = this.planDefinition();
    const effective = plan.canChooseObjective ? (objective ?? plan.defaultObjective) : plan.defaultObjective;

    return this.createScan(targetUrl, effective).pipe(
      switchMap((scan) =>
        this.runScan(scan).pipe(
          map((): StartScanOutcome => ({ scan, runError: null })),
          catchError((message: string) => of<StartScanOutcome>({ scan, runError: message }))
        )
      )
    );
  }

  createScan(targetUrl: string, objective: ScanObjective): Observable<Scan> {
    return this.scanService
      .createScan(targetUrl, objective)
      .pipe(tap((scan) => this.scans.update((scans) => [scan, ...scans])));
  }

  // POST /api/scans/:id/run — o servidor responde 202 e roda em segundo plano.
  // Marcamos o scan como RUNNING na hora e passamos a consultar o backend até
  // ele terminar.
  runScan(scan: Scan): Observable<void> {
    return this.scanService.runScan(scan.id).pipe(
      tap(() => {
        this.patchScan(scan.id, {
          status: 'RUNNING',
          startedAt: new Date().toISOString(),
          finishedAt: null,
        });
        this.ensurePolling();
      }),
      map(() => undefined)
    );
  }

  private patchScan(id: string, patch: Partial<Scan>): void {
    this.scans.update((scans) => scans.map((scan) => (scan.id === id ? { ...scan, ...patch } : scan)));
  }

  // ---------- acompanhamento ----------

  // Enquanto existir scan RUNNING, recarrega a lista a cada
  // SCAN_POLL_INTERVAL_MS. Quando o último terminar, para e busca os findings.
  // BACKEND: se um dia houver SSE/WebSocket de status, troca-se só este método.
  private ensurePolling(): void {
    if (this.pollSubscription || this.runningScans() === 0) {
      return;
    }

    this.pollSubscription = timer(SCAN_POLL_INTERVAL_MS, SCAN_POLL_INTERVAL_MS)
      .pipe(
        // uma falha pontual de rede não derruba o acompanhamento
        switchMap(() => this.scanService.listScans().pipe(catchError(() => EMPTY))),
        takeUntilDestroyed(this.destroyRef)
      )
      .subscribe((scans) => {
        this.scans.set(scans);

        if (!scans.some((scan) => scan.status === 'RUNNING')) {
          this.stopPolling();
          this.loadFindings(scans);
        }
      });
  }

  private stopPolling(): void {
    this.pollSubscription?.unsubscribe();
    this.pollSubscription = null;
  }

  // ---------- UI ----------
  requestScanFocus(): void {
    this.scrollToSection('scan');
    this.scanFocusRequest.update((count) => count + 1);
  }

  scrollToSection(elementId: string): void {
    if (elementId === 'top') {
      this.document.defaultView?.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    this.document.getElementById(elementId)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  toggleHighContrast(): void {
    this.highContrast.update((value) => !value);
  }
}
