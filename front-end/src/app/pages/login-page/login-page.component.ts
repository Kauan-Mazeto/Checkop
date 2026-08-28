import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

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

  protected email = '';
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
        this.router.navigateByUrl('/landing');
      },
      error: (message: string) => {
        this.isSubmitting = false;
        this.errorMessage = message;
      },
    });
  }
}
