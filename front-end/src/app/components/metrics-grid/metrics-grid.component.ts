import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

@Component({
  selector: 'app-metrics-grid',
  templateUrl: './metrics-grid.component.html',
  styleUrl: './metrics-grid.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MetricsGridComponent {
  // Todas as métricas são calculadas em DashboardStateService a partir dos
  // scans reais (GET /api/scans) — nada aqui é número fixo.
  protected readonly state = inject(DashboardStateService);
}
