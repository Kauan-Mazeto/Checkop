import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  ENVIRONMENT_LABEL,
  OBJECTIVE_LABEL,
  OBJECTIVE_OPTIONS,
} from '../../core/constants/dashboard.constants';
import { DashboardStateService } from '../../core/services/dashboard-state.service';
import { ScanObjective } from '../../core/services/scan.service';

interface ScanFeedback {
  message: string;
  ok: boolean;
}

@Component({
  selector: 'app-scan-panel',
  imports: [FormsModule],
  templateUrl: './scan-panel.component.html',
  styleUrl: './scan-panel.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ScanPanelComponent {
  protected readonly state = inject(DashboardStateService);
  private readonly urlInput = viewChild<ElementRef<HTMLInputElement>>('urlInput');

  protected readonly objectiveOptions = OBJECTIVE_OPTIONS;
  protected readonly objectiveLabel = OBJECTIVE_LABEL;

  protected targetUrl = '';
  protected objective: ScanObjective = 'FULL_SCAN';
  protected authorized = false;

  protected readonly isSubmitting = signal(false);
  protected readonly feedback = signal<ScanFeedback | null>(null);

  constructor() {
    // "+ Novo scan" (topbar) incrementa scanFocusRequest; aqui só focamos o campo.
    effect(() => {
      if (this.state.scanFocusRequest() > 0) {
        this.urlInput()?.nativeElement.focus();
      }
    });
  }

  private scanLabel(objective: ScanObjective | undefined): string {
    if (!this.state.planDefinition().canChooseObjective) {
      return 'scan básico';
    }

    return OBJECTIVE_LABEL[objective ?? this.objective];
  }

  protected submit(): void {
    if (this.isSubmitting()) {
      return;
    }

    const url = this.targetUrl.trim();

    if (!url || !this.authorized) {
      this.feedback.set({
        message: 'Informe a URL e confirme que possui autorização para testá-la.',
        ok: false,
      });
      return;
    }

    // BACKEND: o limite de 1 scan por dia do plano Free precisa ser validado
    // também em POST /api/scans. Aqui só impedimos o envio para dar um aviso claro.
    if (this.state.scansRemaining() === 0) {
      this.feedback.set({
        message:
          'Você já usou o scan de hoje. O plano Free permite 1 scan por dia: volte amanhã ou conheça o Premium.',
        ok: false,
      });
      return;
    }

    this.isSubmitting.set(true);
    this.feedback.set(null);

    // 1) POST /api/scans registra o scan (o backend detecta o ambiente sozinho)
    // 2) POST /api/scans/:id/run dispara a execução em segundo plano
    // O tipo de teste só é enviado no Premium; no Free o estado usa o scan básico.
    this.state.startScan(url, this.objective).subscribe({
      next: ({ scan, runError }) => {
        const mode = scan.safeMode ? 'Modo Seguro' : 'Modo Verboso';
        const detected = `Ambiente detectado: ${ENVIRONMENT_LABEL[scan.environment]} · ${mode}.`;
        const suspicious = scan.suspiciousEnvironment
          ? ' Atenção: o ambiente foi sinalizado como suspeito (pode ser produção).'
          : '';

        if (runError) {
          this.feedback.set({
            message: `Scan registrado, mas a execução não iniciou: ${runError} Você pode tentar de novo pelo botão "Executar" no histórico. ${detected}`,
            ok: false,
          });
        } else {
          this.feedback.set({
            message: `Scan iniciado (${this.scanLabel(scan.objective)}). ${detected}${suspicious} O status é atualizado automaticamente.`,
            ok: true,
          });
          this.targetUrl = '';
          this.authorized = false;
        }

        this.isSubmitting.set(false);
      },
      error: (message: string) => {
        this.feedback.set({ message, ok: false });
        this.isSubmitting.set(false);
      },
    });
  }
}
