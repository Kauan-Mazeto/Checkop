import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService, AuthUser, UserRole } from '../../core/services/auth.service';
import { Scan, ScanService } from '../../core/services/scan.service';

// Cada perfil vê UM bloco extra além do núcleo comum (estatísticas +
// "novo scan"). Isso evita ter 4 dashboards/rotas separados — é um
// switch sobre esse mapa, não 4 componentes duplicados. Ver explicação
// completa na conversa; resumo: núcleo igual pra todo mundo, só esse
// slot muda.
type RoleWidget = 'reports' | 'alerts' | 'logs' | 'learning';

const ROLE_WIDGET: Record<UserRole, RoleWidget> = {
  QA: 'reports',
  DEV: 'alerts',
  PENTESTER: 'logs',
  STUDENT: 'learning',
  ADM: 'alerts',
};

const ROLE_LABEL: Record<UserRole, string> = {
  QA: 'QA',
  DEV: 'Dev',
  PENTESTER: 'Pentester',
  STUDENT: 'Estudante',
  ADM: 'Admin',
};

const STATUS_LABEL: Record<Scan['status'], string> = {
  PENDING: 'Pendente',
  RUNNING: 'Em execução',
  COMPLETED: 'Concluído',
  FAILED: 'Falhou',
};

const ENVIRONMENT_LABEL: Record<Scan['environment'], string> = {
  DEVELOPMENT: 'DEV',
  STAGING: 'STAGING',
  PRODUCTION: 'PROD',
};

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './dashboard-page.component.html',
  styleUrl: './dashboard-page.component.scss',
})
export class DashboardPageComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly scanService = inject(ScanService);
  private readonly router = inject(Router);

  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;

  protected user: AuthUser | null = null;
  protected roleLabel = '';
  protected widget: RoleWidget = 'learning';

  protected scans: Scan[] = [];
  protected isLoadingScans = true;
  protected scansError: string | null = null;

  protected isNewScanOpen = false;
  protected newScanUrl = '';
  protected newScanAuthorized = false;
  protected isCreatingScan = false;
  protected newScanError: string | null = null;

  ngOnInit(): void {
    // Pinta a UI na hora com o que já temos em cache (evita tela em
    // branco), mas quem decide de fato se a sessão ainda vale é o
    // backend — por isso a checagem via me() logo em seguida.
    this.user = this.auth.getCachedUser();

    if (!this.user) {
      this.router.navigateByUrl('/login');
      return;
    }

    this.applyRole(this.user.role);

    this.auth.me().subscribe({
      next: (session) => {
        this.user = { ...this.user!, role: session.role, email: session.email };
        this.applyRole(session.role);
        this.loadScans();
      },
      error: () => this.router.navigateByUrl('/login'),
    });
  }

  protected get totalScans(): number {
    return this.scans.length;
  }

  protected get completedScans(): number {
    return this.scans.filter((scan) => scan.status === 'COMPLETED').length;
  }

  protected get suspiciousScans(): number {
    return this.scans.filter((scan) => scan.suspiciousEnvironment).length;
  }

  protected get recentScans(): Scan[] {
    return this.scans.slice(0, 5);
  }

  protected get flaggedScans(): Scan[] {
    return this.scans.filter((scan) => scan.status === 'FAILED' || scan.suspiciousEnvironment).slice(0, 5);
  }

  protected openNewScan(): void {
    this.isNewScanOpen = true;
    this.newScanError = null;
  }

  protected closeNewScan(): void {
    this.isNewScanOpen = false;
  }

  protected submitNewScan(): void {
    if (this.isCreatingScan) {
      return;
    }

    if (!this.newScanUrl.trim() || !this.newScanAuthorized) {
      this.newScanError = 'Informe a URL e confirme que possui autorização para testá-la.';
      return;
    }

    this.isCreatingScan = true;
    this.newScanError = null;

    this.scanService.createScan(this.newScanUrl.trim()).subscribe({
      next: (scan) => {
        this.isCreatingScan = false;
        this.scans = [scan, ...this.scans];
        this.newScanUrl = '';
        this.newScanAuthorized = false;
        this.isNewScanOpen = false;
      },
      error: (message: string) => {
        this.isCreatingScan = false;
        this.newScanError = message;
      },
    });
  }

  protected logout(): void {
    this.auth.logout().subscribe({
      next: () => this.router.navigateByUrl('/landing'),
      error: () => this.router.navigateByUrl('/landing'),
    });
  }

  private applyRole(role: UserRole): void {
    this.roleLabel = ROLE_LABEL[role];
    this.widget = ROLE_WIDGET[role];
  }

  private loadScans(): void {
    this.isLoadingScans = true;
    this.scansError = null;

    this.scanService.listScans().subscribe({
      next: (scans) => {
        this.scans = scans;
        this.isLoadingScans = false;
      },
      error: (message: string) => {
        this.scansError = message;
        this.isLoadingScans = false;
      },
    });
  }
}