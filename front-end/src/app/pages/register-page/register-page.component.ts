import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AccountService } from '../../core/services/account.service';
import { AuthService, RegisterPayload } from '../../core/services/auth.service';
import { DraftService } from '../../core/services/draft.service';
import { GoogleSignInComponent } from '../../shared/components/google-sign-in/google-sign-in.component';
import { PLAN_CARDS, PlanCard, PlanCardId } from '../../shared/ui/plans';

type SelectableRole = RegisterPayload['role'];
type RegisterStep = 1 | 2 | 3;
type PlanId = PlanCardId;

/** Só Free e Premium podem ser escolhidos; o Enterprise é vitrine. */
export const isSelectablePlan = (plan: unknown): plan is PlanId =>
  PLAN_CARDS.some((card) => card.id === plan && card.available);

const REGISTER_DRAFT_KEY = 'register';

interface RegisterDraft {
  name: string;
  email: string;
  selectedRole: SelectableRole | null;
  selectedPlan: PlanId | null;
}

@Component({
  selector: 'app-register-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, GoogleSignInComponent],
  templateUrl: './register-page.component.html',
  styleUrl: './register-page.component.scss',
})
export class RegisterPageComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly account = inject(AccountService);
  private readonly drafts = inject(DraftService);

  // Espelha o enum Role do backend (backend/src/constants/enums.js), exceto
  // ADM, que o próprio registerSchema não permite escolher no cadastro.
  protected readonly roles: { id: SelectableRole; label: string; hint: string }[] = [
    { id: 'QA', label: 'QA', hint: 'Evidência pronta para abrir o chamado' },
    { id: 'DEV', label: 'Dev', hint: 'A linha do problema e a correção' },
    { id: 'PENTESTER', label: 'Pentester', hint: 'Payload, requisição crua e PoC' },
    { id: 'STUDENT', label: 'Estudante', hint: 'Explicação e referências da OWASP' },
  ];

  // Os mesmos cartões da landing (shared/ui/plans.ts). O Enterprise aparece,
  // mas ainda não pode ser escolhido (a definir pela equipe).
  protected readonly plans: PlanCard[] = PLAN_CARDS;

  protected readonly steps: { id: RegisterStep; label: string; hint: string }[] = [
    { id: 1, label: 'Conta', hint: 'Nome, e-mail e senha' },
    { id: 2, label: 'Perfil', hint: 'QA, Dev, Pentester ou Estudante' },
    { id: 3, label: 'Plano', hint: 'Free ou Premium' },
  ];

  protected currentStep: RegisterStep = 1;

  // Nome, e-mail, perfil e plano sobrevivem a recarregar/voltar (sessionStorage).
  // A senha nunca é guardada.
  private readonly draft = this.drafts.load<RegisterDraft>(REGISTER_DRAFT_KEY);
  private _name = this.draft.name ?? '';
  private _email = this.draft.email ?? '';
  protected password = '';
  protected selectedRole: SelectableRole | null = this.draft.selectedRole ?? null;
  // rascunho antigo pode trazer um plano que não existe mais (ex.: "PRO")
  protected selectedPlan: PlanId | null = isSelectablePlan(this.draft.selectedPlan) ? this.draft.selectedPlan : null;

  protected get name(): string {
    return this._name;
  }

  protected set name(value: string) {
    this._name = value;
    this.saveDraft();
  }

  protected get email(): string {
    return this._email;
  }

  protected set email(value: string) {
    this._email = value;
    this.saveDraft();
  }

  private saveDraft(): void {
    this.drafts.save<RegisterDraft>(REGISTER_DRAFT_KEY, {
      name: this._name,
      email: this._email,
      selectedRole: this.selectedRole,
      selectedPlan: this.selectedPlan,
    });
  }
  protected termsAccepted = false;
  protected showPassword = false;
  protected isSubmitting = false;
  /** o botão do Google só aparece se o servidor tiver GOOGLE_CLIENT_ID */
  protected googleAvailable = false;

  /** conta criada (ou já existente) pelo Google: o perfil foi escolhido no primeiro acesso */
  protected onGoogleSignedIn(): void {
    this.drafts.clear(REGISTER_DRAFT_KEY);
    this.router.navigateByUrl('/dashboard');
  }
  protected errorMessage: string | null = null;

  protected get isAccountStepValid(): boolean {
    return (
      this.name.trim().length >= 2 && this.isValidEmail(this.email) && this.password.length >= 8
    );
  }

  protected togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  protected selectRole(role: SelectableRole): void {
    this.selectedRole = role;
    this.errorMessage = null;
    this.saveDraft();
  }

  protected selectPlan(plan: PlanId): void {
    if (!isSelectablePlan(plan)) return; // Enterprise: só vitrine por enquanto
    this.selectedPlan = plan;
    this.errorMessage = null;
    this.saveDraft();
  }

  protected goToStep(step: RegisterStep): void {
    // Só permite pular pra frente por etapas já validadas — evita ir direto
    // pro passo 3 sem ter escolhido um perfil, por exemplo.
    if (step > 1 && !this.isAccountStepValid) {
      return;
    }

    if (step > 2 && !this.selectedRole) {
      return;
    }

    this.errorMessage = null;
    this.currentStep = step;
  }

  protected nextStep(): void {
    this.errorMessage = null;

    if (this.currentStep === 1) {
      if (!this.isAccountStepValid) {
        this.errorMessage = 'Preencha nome, e-mail e uma senha de pelo menos 8 caracteres.';
        return;
      }

      this.currentStep = 2;
      return;
    }

    if (this.currentStep === 2) {
      if (!this.selectedRole) {
        this.errorMessage = 'Selecione seu perfil para continuar.';
        return;
      }

      this.currentStep = 3;
    }
  }

  protected prevStep(): void {
    this.errorMessage = null;

    if (this.currentStep > 1) {
      this.currentStep = (this.currentStep - 1) as RegisterStep;
    }
  }

  protected submit(): void {
    if (this.isSubmitting) {
      return;
    }

    if (!this.isAccountStepValid) {
      this.currentStep = 1;
      this.errorMessage = 'Preencha nome, e-mail e uma senha de pelo menos 8 caracteres.';
      return;
    }

    if (!this.selectedRole) {
      this.currentStep = 2;
      this.errorMessage = 'Selecione seu perfil para continuar.';
      return;
    }

    if (!this.selectedPlan) {
      this.errorMessage = 'Selecione um plano para continuar.';
      return;
    }

    if (!this.termsAccepted) {
      this.errorMessage = 'Você precisa aceitar os termos de uso para concluir o cadastro.';
      return;
    }

    this.isSubmitting = true;
    this.errorMessage = null;

    const payload: RegisterPayload = {
      name: this.name.trim(),
      // trim/lowercase espelha o pré-processamento do zod no backend
      // (z.string().trim().toLowerCase().email(...) em auth_validator.js).
      email: this.email.trim().toLowerCase(),
      password: this.password,
      role: this.selectedRole,
      termsAccepted: true,
    };

    // A conta nasce no Free; quem escolheu o Premium já sai com ele ativado
    // (troca demonstrativa, sem cobrança: TCC 6.3).
    const wantsPremium = this.selectedPlan === 'PREMIUM';
    this.auth.register(payload).subscribe({
      next: () => {
        this.drafts.clear(REGISTER_DRAFT_KEY);
        const goToDashboard = () => {
          this.isSubmitting = false;
          this.router.navigateByUrl('/dashboard');
        };
        if (!wantsPremium) return goToDashboard();
        this.account.changePlan('PREMIUM').subscribe({ next: goToDashboard, error: goToDashboard });
      },
      error: (message: string) => {
        this.isSubmitting = false;
        this.errorMessage = message;
      },
    });
  }

  private isValidEmail(value: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
  }
}