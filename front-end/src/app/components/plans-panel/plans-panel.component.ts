import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { PLAN_DEFINITIONS, PLAN_ORDER } from '../../core/constants/dashboard.constants';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

@Component({
  selector: 'app-plans-panel',
  templateUrl: './plans-panel.component.html',
  styleUrl: './plans-panel.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PlansPanelComponent {
  protected readonly state = inject(DashboardStateService);

  protected readonly plans = PLAN_ORDER.map((tier) => PLAN_DEFINITIONS[tier]);
}
