import {
  AfterViewInit,
  Component,
  ElementRef,
  Input,
  OnChanges,
  OnDestroy,
  ViewChild,
} from '@angular/core';
import {
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  Chart,
  ChartData,
  ChartOptions,
  ChartType,
  DoughnutController,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js';

// Registra só o que é usado (tree-shaking): rosca, barras e linha.
Chart.register(
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip
);

const TEXT = '#d5d5d8';
const MUTED = '#b0b0b5';
const GRID = 'rgba(255, 255, 255, 0.06)';

// Visual dos gráficos alinhado aos tokens das telas logadas (escuro suave).
Chart.defaults.color = MUTED;
Chart.defaults.font.family = "system-ui, -apple-system, 'Segoe UI', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.borderColor = GRID;
Chart.defaults.plugins.legend.labels.color = TEXT;
Chart.defaults.plugins.tooltip.backgroundColor = '#202124';
Chart.defaults.plugins.tooltip.borderColor = '#46474c';
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.padding = 10;

/**
 * Wrapper mínimo do Chart.js (biblioteca definida na proposta do TCC, seção 7.1).
 * Recria o gráfico quando os dados mudam.
 */
@Component({
  selector: 'app-chart',
  standalone: true,
  template: `
    <div class="chart-box" [style.height.px]="height">
      <canvas #canvas [attr.aria-label]="ariaLabel" role="img" [class.dimmed]="empty"></canvas>
      @if (empty) {
        <div class="chart-empty">{{ emptyText }}</div>
      }
    </div>
  `,
  styles: [
    `:host { display: block; }
     .chart-box { position: relative; width: 100%; }
     canvas.dimmed { opacity: 0.25; }
     .chart-empty { position: absolute; inset: 0; display: grid; place-items: center; padding: 16px;
       color: #b0b0b5; font-size: 13px; text-align: center; }`,
  ],
})
export class ChartComponent implements AfterViewInit, OnChanges, OnDestroy {
  @Input({ required: true }) type!: ChartType;
  @Input({ required: true }) data!: ChartData;
  @Input() options: ChartOptions = {};
  @Input() height = 220;
  @Input() ariaLabel = 'Gráfico';
  /** sem dados: o gráfico aparece esmaecido com a mensagem por cima (não some) */
  @Input() empty = false;
  @Input() emptyText = 'Sem dados ainda. Rode uma varredura para preencher este gráfico.';

  @ViewChild('canvas') private canvas?: ElementRef<HTMLCanvasElement>;
  private chart?: Chart;

  ngAfterViewInit(): void {
    this.render();
  }

  ngOnChanges(): void {
    if (this.canvas) this.render();
  }

  ngOnDestroy(): void {
    this.chart?.destroy();
  }

  private render(): void {
    this.chart?.destroy();
    if (!this.canvas) return;
    this.chart = new Chart(this.canvas.nativeElement, {
      type: this.type,
      data: this.data,
      options: { responsive: true, maintainAspectRatio: false, ...this.options },
    });
  }
}
