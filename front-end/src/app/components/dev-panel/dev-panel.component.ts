import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

@Component({
  selector: 'app-dev-panel',
  imports: [DatePipe],
  templateUrl: './dev-panel.component.html',
  styleUrl: './dev-panel.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DevPanelComponent {
  protected readonly state = inject(DashboardStateService);

  // Sugestões de correção vêm do campo `remediation` de cada Finding.
  protected readonly fixSuggestions = computed(() =>
    this.state
      .findings()
      .filter((finding) => !!finding.remediation)
      .slice(0, 5)
  );
}
