import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ROLE_LABEL } from '../../core/constants/dashboard.constants';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

@Component({
  selector: 'app-dashboard-topbar',
  templateUrl: './dashboard-topbar.component.html',
  styleUrl: './dashboard-topbar.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardTopbarComponent {
  protected readonly state = inject(DashboardStateService);
  protected readonly roleLabel = ROLE_LABEL;
}
