import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService, RegisterPayload } from '../../core/services/auth.service';

type SelectableRole = RegisterPayload['role'];
type RegisterStep = 1 | 2 | 3;
type PlanId = 'FREE' | 'PRO' | 'ENTERPRISE';

interface PlanOption {
  id: PlanId;
  name: string;
  price: string;
  period: string;
  features: string[];
  badge?: string;
}

@Component({
  selector: 'app-register-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './register-page.component.html',
  styleUrl: './register-page.component.scss',
})
export class RegisterPageComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  // Espelha o enum Role do backend (backend/src/constants/enums.js), exceto
  // ADM, que o próprio registerSchema não permite escolher no cadastro.
  protected readonly roles: { id: SelectableRole; label: string }[] = [
    { id: 'QA', label: 'QA' },
    { id: 'DEV', label: 'Dev' },
    { id: 'PENTESTER', label: 'Pentester' },
    { id: 'STUDENT', label: 'Estudante' },
  ];

  // Mesmos planos exibidos na landing page (ver seção #pricing em
  // landing-page.component.html), só que aqui como passo final do cadastro.
  // O backend ainda não tem um campo de plano no model User (ver
  // backend/prisma/schema.prisma), então essa escolha por enquanto só define
  // o texto do botão final e fica guardada no cliente — ver comentário em
  // submit().
  protected readonly plans: PlanOption[] = [
    {
      id: 'FREE',
      name: 'Free',
      price: 'R$0',
      period: '/mês',
      features: ['5 scans/mês', 'Relatório básico', '3 vetores de ataque'],
    },
    {
      id: 'PRO',
      name: 'Pro',
      price: 'R$97',
      period: '/mês',
      features: ['Scans ilimitados', 'Relatório completo', '14 vetores de ataque'],
      badge: 'Mais popular',
    },
    {
      id: 'ENTERPRISE',
      name: 'Enterprise',
      price: 'Custom',
      period: 'sob consulta',
      features: ['Tudo do Pro', 'API dedicada', 'Suporte prioritário'],
    },
  ];

  protected readonly steps: { id: RegisterStep; label: string }[] = [
    { id: 1, label: 'Conta' },
    { id: 2, label: 'Perfil' },
    { id: 3, label: 'Plano' },
  ];

  protected currentStep: RegisterStep = 1;

  protected name = '';
  protected email = '';
  protected password = '';
  protected selectedRole: SelectableRole | null = null;
  protected selectedPlan: PlanId | null = null;
  protected showPassword = false;
  protected isSubmitting = false;
  protected errorMessage: string | null = null;

  protected get isAccountStepValid(): boolean {
    return (
      this.name.trim().length >= 2 &&
      this.isValidEmail(this.email) &&
      this.password.length >= 8
    );
  }

  protected togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  protected selectRole(role: SelectableRole): void {
    this.selectedRole = role;
    this.errorMessage = null;
  }

  protected selectPlan(plan: PlanId): void {
    this.selectedPlan = plan;
    this.errorMessage = null;
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

    this.isSubmitting = true;
    this.errorMessage = null;

    const payload: RegisterPayload = {
      name: this.name.trim(),
      // trim/lowercase espelha o pré-processamento do zod no backend
      // (z.string().trim().toLowerCase().email(...) em auth_validator.js).
      email: this.email.trim().toLowerCase(),
      password: this.password,
      role: this.selectedRole,
    };

    // TODO: quando o backend ganhar suporte a plano/assinatura (hoje o
    // model User em backend/prisma/schema.prisma não tem esse campo),
    // enviar this.selectedPlan junto — seja no próprio POST /auth/register,
    // seja numa chamada separada de billing logo em seguida.
    this.auth.register(payload).subscribe({
      next: () => {
        this.isSubmitting = false;
        this.router.navigateByUrl('/landing');
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