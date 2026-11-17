import { CommonModule } from '@angular/common';
import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  ElementRef,
  EventEmitter,
  Input,
  NgZone,
  Output,
  ViewChild,
  inject,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '../../../core/http/api-error';
import { AuthService, AuthUser, UserRole } from '../../../core/services/auth.service';
import { GoogleAuthService } from '../../../core/services/google-auth.service';

type SelectableRole = Exclude<UserRole, 'ADM'>;

/** Nome e e-mail do id_token, só para mostrar na tela (quem confere é o backend). */
export const readGoogleIdentity = (credential: string): { name: string | null; email: string | null } => {
  try {
    const payload = credential.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(payload)
        .split('')
        .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('')
    );
    const data = JSON.parse(json) as { name?: string; email?: string };
    return { name: data.name ?? null, email: data.email ?? null };
  } catch {
    return { name: null, email: null };
  }
};

/**
 * Botão oficial "Continuar com Google" + primeiro acesso.
 * Fluxo: o Google devolve o id_token → POST /api/auth/google. Se a conta ainda
 * não aceitou os termos (backend: TERMS_REQUIRED), a tela pede o aceite e o
 * perfil, igual ao cadastro por e-mail, e reenvia o mesmo token.
 * Se o servidor não tiver GOOGLE_CLIENT_ID, o componente não aparece.
 */
@Component({
  selector: 'app-google-sign-in',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="google-slot" #slot [hidden]="!enabled || pendingCredential"></div>

    <p *ngIf="isSubmitting && !pendingCredential" class="g-status" role="status">Entrando com Google...</p>

    <section *ngIf="pendingCredential" class="g-first" aria-labelledby="g-first-title">
      <h3 id="g-first-title">Primeiro acesso com Google</h3>
      <p class="g-who" *ngIf="identity.email">{{ identity.name || identity.email }} <span *ngIf="identity.name">· {{ identity.email }}</span></p>
      <p>Para concluir, escolha como você vai usar o Checkop e aceite os termos.</p>

      <div class="g-roles" role="radiogroup" aria-label="Perfil de uso">
        <button
          *ngFor="let r of roles"
          type="button"
          role="radio"
          class="g-role"
          [class.selected]="role === r.id"
          [attr.aria-checked]="role === r.id"
          (click)="role = r.id"
        >
          <strong>{{ r.label }}</strong>
          <span>{{ r.hint }}</span>
        </button>
      </div>

      <label class="g-terms">
        <input type="checkbox" name="googleTerms" [(ngModel)]="termsAccepted" />
        <span>
          Aceito os <a routerLink="/terms" target="_blank" rel="noopener">termos de uso</a> e a
          <a routerLink="/privacy" target="_blank" rel="noopener">política de privacidade</a>.
        </span>
      </label>

      <div class="g-actions">
        <button class="g-primary" type="button" [disabled]="isSubmitting || !termsAccepted" (click)="completeFirstAccess()">
          {{ isSubmitting ? 'Criando acesso...' : 'Concluir e entrar' }}
        </button>
        <button class="g-ghost" type="button" [disabled]="isSubmitting" (click)="cancelFirstAccess()">Cancelar</button>
      </div>
    </section>

    <p *ngIf="errorMessage" class="g-error" role="alert">{{ errorMessage }}</p>
  `,
  styles: [
    `
      :host {
        display: block;
      }
      .google-slot {
        display: flex;
        justify-content: center;
        min-height: 44px;
      }
      .g-status {
        margin: 8px 0 0;
        color: var(--muted, #b0b0b5);
        font-size: 13px;
        text-align: center;
      }
      .g-first {
        padding: 16px;
        border: 1px solid #303135;
        border-radius: 6px;
        background: var(--surface-light, #202124);
        color: var(--text, #f1f1f2);
      }
      .g-first h3 {
        margin: 0 0 4px;
        font-size: 15px;
      }
      .g-first p {
        margin: 0 0 10px;
        color: var(--muted, #b0b0b5);
        font-size: 13px;
      }
      .g-who {
        color: var(--text, #f1f1f2) !important;
        font-weight: 600;
      }
      .g-roles {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
        margin-bottom: 12px;
      }
      .g-role {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 10px;
        border: 1px solid #46474c;
        border-radius: 5px;
        background: var(--surface, #191a1c);
        color: var(--text, #f1f1f2);
        text-align: left;
        cursor: pointer;
      }
      .g-role span {
        color: var(--muted, #b0b0b5);
        font-size: 11.5px;
      }
      .g-role.selected {
        border-color: var(--primary, #d84a56);
        background: #261218;
      }
      .g-terms {
        display: flex;
        gap: 8px;
        align-items: flex-start;
        color: var(--muted, #b0b0b5);
        font-size: 12.5px;
      }
      .g-terms input {
        margin-top: 2px;
        accent-color: var(--primary, #d84a56);
      }
      .g-terms a {
        color: var(--text, #f1f1f2);
        text-decoration: underline;
      }
      .g-actions {
        display: flex;
        gap: 8px;
        margin-top: 14px;
      }
      .g-primary,
      .g-ghost {
        min-height: 40px;
        padding: 0 16px;
        border-radius: 5px;
        font-weight: 600;
        cursor: pointer;
      }
      .g-primary {
        flex: 1;
        border: 1px solid var(--primary, #d84a56);
        background: var(--primary, #d84a56);
        color: #fff;
      }
      .g-ghost {
        border: 1px solid #444549;
        background: transparent;
        color: var(--text, #f1f1f2);
      }
      .g-primary:disabled,
      .g-ghost:disabled {
        cursor: not-allowed;
        opacity: 0.5;
      }
      .g-error {
        margin: 10px 0 0;
        padding: 10px 12px;
        border: 1px solid #5b2633;
        border-radius: 6px;
        background: #271218;
        color: #e6b9bd;
        font-size: 13px;
      }
      @media (max-width: 420px) {
        .g-roles {
          grid-template-columns: minmax(0, 1fr);
        }
      }
    `,
  ],
})
export class GoogleSignInComponent implements AfterViewInit {
  private readonly google = inject(GoogleAuthService);
  private readonly auth = inject(AuthService);
  private readonly zone = inject(NgZone);
  private readonly cdr = inject(ChangeDetectorRef);

  /** Avisa a página se o botão vai aparecer (para mostrar o divisor "ou ..."). */
  @Output() readonly available = new EventEmitter<boolean>();
  /** Login concluído: a sessão (cookie) já está ativa. */
  @Output() readonly signedIn = new EventEmitter<AuthUser>();
  /** Enquanto true, o botão não reage (ex.: login por senha em andamento). */
  @Input() disabled = false;

  @ViewChild('slot', { static: true }) private slot!: ElementRef<HTMLElement>;

  protected readonly roles: { id: SelectableRole; label: string; hint: string }[] = [
    { id: 'QA', label: 'QA', hint: 'Relatórios e gráficos' },
    { id: 'DEV', label: 'Dev', hint: 'Alertas e correções' },
    { id: 'PENTESTER', label: 'Pentester', hint: 'Payloads e logs' },
    { id: 'STUDENT', label: 'Estudante', hint: 'Explicações' },
  ];

  protected enabled = false;
  protected isSubmitting = false;
  protected errorMessage: string | null = null;
  protected pendingCredential: string | null = null;
  protected identity: { name: string | null; email: string | null } = { name: null, email: null };
  protected role: SelectableRole = 'DEV';
  protected termsAccepted = false;

  async ngAfterViewInit(): Promise<void> {
    const config = await this.google.getConfig();
    this.enabled = Boolean(config.enabled && config.clientId);
    this.available.emit(this.enabled);
    this.cdr.detectChanges();
    if (!this.enabled) return;

    try {
      await this.google.renderButton(this.slot.nativeElement, config.clientId!, (credential) =>
        // o callback vem do script do Google: volta para a zona do Angular
        this.zone.run(() => this.signIn(credential))
      );
    } catch (error) {
      this.errorMessage = (error as Error).message;
      this.cdr.detectChanges();
    }
  }

  private signIn(credential: string, extras: { termsAccepted?: true; role?: SelectableRole } = {}): void {
    if (this.disabled || this.isSubmitting) return;
    this.isSubmitting = true;
    this.errorMessage = null;

    this.auth.googleLogin(credential, extras).subscribe({
      next: (user) => {
        this.isSubmitting = false;
        this.pendingCredential = null;
        this.signedIn.emit(user);
      },
      error: (error: ApiError) => {
        this.isSubmitting = false;
        if (error.code === 'TERMS_REQUIRED') {
          // primeiro acesso: guarda o token e pede aceite + perfil
          this.pendingCredential = credential;
          this.identity = readGoogleIdentity(credential);
          return;
        }
        this.pendingCredential = null;
        this.errorMessage =
          error.status === 401
            ? 'O Google não confirmou o login. Tente de novo; se continuar, confira se a origem deste site está autorizada no projeto do Google.'
            : error.message;
      },
    });
  }

  protected completeFirstAccess(): void {
    if (!this.pendingCredential || !this.termsAccepted) return;
    this.signIn(this.pendingCredential, { termsAccepted: true, role: this.role });
  }

  protected cancelFirstAccess(): void {
    this.pendingCredential = null;
    this.termsAccepted = false;
    this.errorMessage = null;
  }
}
