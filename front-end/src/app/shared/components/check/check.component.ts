import { Component, EventEmitter, Input, Output } from '@angular/core';

/**
 * Checkbox em cartão, para termos e declarações. Uso:
 * <app-check [(checked)]="aceito"><strong>Título</strong> Texto da declaração.</app-check>
 * Continua sendo um <input type="checkbox"> de verdade (teclado e leitor de tela).
 */
@Component({
  selector: 'app-check',
  standalone: true,
  template: `
    <label class="check" [class.checked]="checked">
      <input type="checkbox" [checked]="checked" [disabled]="disabled" (change)="toggle($event)" />
      <span class="check-box" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M5 12.5 10 17 19 7" />
        </svg>
      </span>
      <span class="check-text"><ng-content></ng-content></span>
    </label>
  `,
  styles: [':host { display: block; } label { position: relative; }'],
})
export class CheckComponent {
  @Input() checked = false;
  @Input() disabled = false;
  @Output() checkedChange = new EventEmitter<boolean>();

  protected toggle(event: Event): void {
    this.checked = (event.target as HTMLInputElement).checked;
    this.checkedChange.emit(this.checked);
  }
}
