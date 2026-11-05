import { ChangeDetectionStrategy, Component, OnInit, ViewEncapsulation, inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { PlanService } from '../../core/services/plan.service';
import { DashboardSidebarComponent } from '../../components/dashboard-sidebar/dashboard-sidebar.component';
import { DashboardTopbarComponent } from '../../components/dashboard-topbar/dashboard-topbar.component';
import { ScanPanelComponent } from '../../components/scan-panel/scan-panel.component';
import { MetricsGridComponent } from '../../components/metrics-grid/metrics-grid.component';
import { QaPanelComponent } from '../../components/qa-panel/qa-panel.component';
import { DevPanelComponent } from '../../components/dev-panel/dev-panel.component';
import { PentesterPanelComponent } from '../../components/pentester-panel/pentester-panel.component';
import { StudentPanelComponent } from '../../components/student-panel/student-panel.component';
import { HistoryTableComponent } from '../../components/history-table/history-table.component';
import { PlansPanelComponent } from '../../components/plans-panel/plans-panel.component';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

@Component({
  selector: 'app-dashboard-page',
  imports: [
    DashboardSidebarComponent,
    DashboardTopbarComponent,
    ScanPanelComponent,
    MetricsGridComponent,
    QaPanelComponent,
    DevPanelComponent,
    PentesterPanelComponent,
    StudentPanelComponent,
    HistoryTableComponent,
    PlansPanelComponent,
  ],
  // O estado é da página: os componentes filhos injetam a MESMA instância.
  providers: [DashboardStateService],
  templateUrl: './Dashboard-page.component.html',
  styleUrl: './Dashboard-page.component.scss',
  // None + estilos escopados em `app-dashboard-page` (ver o .scss): os tokens e
  // as classes compartilhadas valem para os componentes filhos sem vazar para
  // as outras páginas.
  encapsulation: ViewEncapsulation.None,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardPageComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly planService = inject(PlanService);
  protected readonly state = inject(DashboardStateService);

  ngOnInit(): void {
    // Pinta a UI na hora com o que já temos em cache (evita tela em
    // branco), mas quem decide de fato se a sessão ainda vale é o
    // backend — por isso a checagem via me() logo em seguida.
    const cachedUser = this.auth.getCachedUser();

    if (!cachedUser) {
      this.router.navigateByUrl('/login');
      return;
    }

    this.state.user.set(cachedUser);
    // plano: vem da sessão quando o backend informar (ver PlanService)
    this.planService.applySession(cachedUser);

    this.auth.me().subscribe({
      next: (session) => {
        this.planService.applySession(session);
        this.state.user.update((user) =>
          user ? { ...user, role: session.role, email: session.email } : user
        );
        this.state.loadScans();
      },
      error: () => this.router.navigateByUrl('/login'),
    });
  }
}
