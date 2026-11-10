import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { DraftService } from '../../core/services/draft.service';

@Component({
  selector: 'app-login-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './login-page.component.html',
  styleUrl: './login-page.component.scss',
})
export class LoginPageComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly drafts = inject(DraftService);

  // o e-mail sobrevive a recarregar/voltar; a senha nunca é guardada
  private _email = this.drafts.load<{ email: string }>('login').email ?? '';

  protected get email(): string {
    return this._email;
  }

  protected set email(value: string) {
    this._email = value;
    this.drafts.save('login', { email: value });
  }
  protected password = '';
  protected isSubmitting = false;
  protected errorMessage: string | null = null;
  protected showPassword = false;

  protected togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  protected submit(form: NgForm): void {
    if (this.isSubmitting) {
      return;
    }

    if (form.invalid) {
      this.errorMessage = 'Preencha e-mail e senha para continuar.';
      return;
    }

    this.isSubmitting = true;
    this.errorMessage = null;

    // trim/lowercase espelha o pré-processamento do zod no backend
    // (z.string().trim().toLowerCase().email(...) em auth_validator.js),
    // então erros de digitação óbvios já chegam normalizados na API.
    const normalizedEmail = this.email.trim().toLowerCase();

    this.auth.login(normalizedEmail, this.password).subscribe({
      next: () => {
        this.isSubmitting = false;
        this.drafts.clear('login');
        this.router.navigateByUrl('/dashboard');
      },
      error: (message: string) => {
        this.isSubmitting = false;
        this.errorMessage = message;
      },
    });
  }
}