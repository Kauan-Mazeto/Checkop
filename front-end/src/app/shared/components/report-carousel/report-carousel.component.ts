import { Component, Input, OnChanges } from '@angular/core';
import { ChartData, ChartOptions, ChartType } from 'chart.js';
import { ChartComponent } from '../chart/chart.component';

/** Um relatório do card: título, gráfico e o texto quando ainda não há dados. */
export interface ReportSlide {
  title: string;
  subtitle?: string;
  type: ChartType;
  data: ChartData;
  options: ChartOptions;
  /** altura do gráfico; sem ela, barras crescem com o número de linhas */
  height?: number;
  empty?: boolean;
  emptyText?: string;
  ariaLabel: string;
}

/**
 * Um card só que troca entre vários relatórios: seta de cada lado e as bolinhas
 * embaixo mostram qual está aberto. Setas do teclado também trocam.
 */
@Component({
  selector: 'app-report-carousel',
  standalone: true,
  imports: [ChartComponent],
  template: `
    @if (current; as slide) {
      <section class="dash-tile carousel" [attr.aria-label]="slide.title" aria-roledescription="carrossel"
        tabindex="0" (keydown.arrowleft)="step(-1)" (keydown.arrowright)="step(1)">
        <header class="dash-tile-head">
          <h3 aria-live="polite">{{ slide.title }}</h3>
          @if (slide.subtitle) {
            <span>{{ slide.subtitle }}</span>
          }
        </header>

        <div class="carousel-body">
          @if (slides.length > 1) {
            <button type="button" class="carousel-arrow" aria-label="Relatório anterior" (click)="step(-1)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m15 18-6-6 6-6"></path></svg>
            </button>
          }
          <div class="carousel-chart">
            <app-chart [type]="slide.type" [data]="slide.data" [options]="slide.options" [height]="heightOf(slide)"
              [empty]="!!slide.empty" [emptyText]="slide.emptyText || 'Sem dados ainda. Rode uma varredura para preencher este gráfico.'"
              [ariaLabel]="slide.ariaLabel" />
          </div>
          @if (slides.length > 1) {
            <button type="button" class="carousel-arrow" aria-label="Próximo relatório" (click)="step(1)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m9 18 6-6-6-6"></path></svg>
            </button>
          }
        </div>

        @if (slides.length > 1) {
          <div class="carousel-dots" role="tablist" aria-label="Escolher relatório">
            @for (s of slides; track s.title; let i = $index) {
              <button type="button" role="tab" class="carousel-dot" [class.active]="i === index" [attr.aria-selected]="i === index"
                [attr.aria-label]="s.title" [title]="s.title" (click)="index = i"></button>
            }
          </div>
        }
      </section>
    }
  `,
  styles: [
    `
      :host { display: block; min-width: 0; }
      .carousel { height: 100%; outline: none; }
      .carousel:focus-visible { box-shadow: 0 0 0 2px var(--info, #79b8ff); }
      .carousel-body { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 6px; flex: 1; }
      .carousel-chart { min-width: 0; }
      .carousel-arrow {
        display: inline-grid; place-items: center; width: 32px; height: 32px; padding: 0;
        border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 50%;
        background: rgba(255, 255, 255, 0.03); color: var(--muted, #b0b0b5); cursor: pointer;
      }
      .carousel-arrow:hover { color: var(--text, #f1f1f2); background: rgba(255, 255, 255, 0.08); }
      .carousel-arrow:focus-visible { outline: 2px solid var(--info, #79b8ff); outline-offset: 2px; }
      .carousel-dots { display: flex; justify-content: center; gap: 4px; }
      /* área de toque de 24px, bolinha visível de 8px */
      .carousel-dot {
        position: relative; width: 24px; height: 24px; padding: 0; border: 0; background: none; cursor: pointer;
      }
      .carousel-dot::after {
        content: ''; position: absolute; inset: 8px; border-radius: 50%; background: rgba(255, 255, 255, 0.22);
        transition: background 0.15s ease, transform 0.15s ease;
      }
      .carousel-dot:hover::after { background: rgba(255, 255, 255, 0.45); }
      .carousel-dot.active::after { background: var(--brand, #d84a56); transform: scale(1.15); }
      .carousel-dot:focus-visible { outline: 2px solid var(--info, #79b8ff); outline-offset: -2px; border-radius: 50%; }
    `,
  ],
})
export class ReportCarouselComponent implements OnChanges {
  @Input({ required: true }) slides: ReportSlide[] = [];
  /** altura mínima do gráfico (as barras podem crescer além dela) */
  @Input() minHeight = 200;

  protected index = 0;

  ngOnChanges(): void {
    if (this.index >= this.slides.length) this.index = 0;
  }

  protected get current(): ReportSlide | null {
    return this.slides[this.index] ?? null;
  }

  protected step(delta: number): void {
    const total = this.slides.length;
    if (total) this.index = (this.index + delta + total) % total;
  }

  /** Barras deitadas crescem com o número de linhas, para nenhum rótulo ficar espremido. */
  protected heightOf(slide: ReportSlide): number {
    if (slide.height) return slide.height;
    const horizontal = slide.type === 'bar' && (slide.options as { indexAxis?: string }).indexAxis === 'y';
    const rows = slide.data.labels?.length ?? 0;
    return horizontal ? Math.max(this.minHeight, rows * 30 + 40) : this.minHeight;
  }
}
