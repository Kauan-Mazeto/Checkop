import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { SEVERITY_LABEL } from '../../core/constants/dashboard.constants';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

@Component({
  selector: 'app-student-panel',
  templateUrl: './student-panel.component.html',
  styleUrl: './student-panel.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StudentPanelComponent {
  protected readonly state = inject(DashboardStateService);
  protected readonly severityLabel = SEVERITY_LABEL;

  // Perfil educativo: mostra o que é, por que acontece e como corrigir
  // (title/description/remediation/owaspUrl). Nunca mostra payload cru.
  protected readonly explainedFindings = computed(() => this.state.findings().slice(0, 5));
}
