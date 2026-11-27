import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { ApiError } from '../../core/http/api-error';
import { AccountService } from '../../core/services/account.service';
import { AuthService, UserPlan } from '../../core/services/auth.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ENTERPRISE_FEATURES, PLAN_FEATURES } from '../../shared/ui/plans';

@Component({
  selector: 'app-plans-page',
  standalone: true,
  imports: [CommonModule, AppShellComponent],
  templateUrl: './plans-page.component.html',
  styleUrl: './plans-page.component.scss',
})
export class PlansPageComponent {
  private readonly auth = inject(AuthService);
  private readonly account = inject(AccountService);

  protected readonly features = PLAN_FEATURES;
  protected readonly enterpriseFeatures = ENTERPRISE_FEATURES;
  /** contato comercial do plano Empresarial (preço e condições combinados com a empresa) */
  protected readonly salesEmail = 'comercial@checkop.com.br';
  protected readonly freeFeatures = PLAN_FEATURES.filter((f) => f.free);
  protected plan: UserPlan = this.auth.getCachedUser()?.plan ?? 'FREE';
  protected isChanging = false;
  protected message: { type: 'success' | 'error'; text: string } | null = null;

  protected get isPremium(): boolean {
    return this.plan === 'PREMIUM';
  }

  protected choose(plan: UserPlan): void {
    if (this.isChanging || plan === this.plan) return;
    this.isChanging = true;
    this.message = null;
    this.account.changePlan(plan).subscribe({
      next: (user) => {
        this.isChanging = false;
        this.plan = user.plan ?? plan;
        this.message = {
          type: 'success',
          text: plan === 'PREMIUM' ? 'Premium ativado! Os recursos avançados já estão liberados.' : 'Você voltou para o plano Free.',
        };
      },
      error: (error: ApiError) => {
        this.isChanging = false;
        this.message = { type: 'error', text: error.message };
      },
    });
  }
}
