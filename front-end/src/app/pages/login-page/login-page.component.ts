import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';

import { environment } from '../../../environments/environment';
import { AuthService } from '../../core/services/auth.service';

type GoogleIdentityNotification = {
  isNotDisplayed?: () => boolean;
  isSkippedMoment?: () => boolean;
};

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: Record<string, unknown>) => void;
          prompt: (callback?: (notification: GoogleIdentityNotification) => void) => void;
        };
      };
    };
    CHECKOP_GOOGLE_CLIENT_ID?: string;
  }
}

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
  private googleScriptPromise: Promise<void> | null = null;

  protected email = '';
  protected password = '';
  protected isSubmitting = false;
  protected isGoogleSubmitting = false;
  protected errorMessage: string | null = null;
  protected showPassword = false;

  protected togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  protected loginWithGoogle(): void {
    if (this.isSubmitting || this.isGoogleSubmitting) {
      return;
    }

    const clientId = this.getGoogleClientId();

    if (!clientId) {
      this.errorMessage = 'Client ID do Google não foi configurado.';
      return;
    }

    this.isGoogleSubmitting = true;
    this.errorMessage = null;

    this.loadGoogleScript()
      .then(() => {
        const google = window.google?.accounts?.id;

        if (!google) {
          throw new Error('Google Identity Services indisponível.');
        }

        google.initialize({
          client_id: clientId,
          callback: (response: { credential?: string }) => {
            if (!response?.credential) {
              this.isGoogleSubmitting = false;
              this.errorMessage = 'Não foi possível concluir o login com Google.';
              return;
            }

            this.auth.googleLogin(response.credential).subscribe({
              next: () => {
                this.isGoogleSubmitting = false;
                this.router.navigateByUrl('/dashboard');
              },
              error: (message: string) => {
                this.isGoogleSubmitting = false;
                this.errorMessage = message;
              },
            });
          },
          auto_select: false,
          cancel_on_tap_outside: false,
        });

        google.prompt((notification) => {
          if (notification?.isNotDisplayed?.() || notification?.isSkippedMoment?.()) {
            this.isGoogleSubmitting = false;
            this.errorMessage = 'O login do Google não foi exibido. Tente novamente.';
          }
        });
      })
      .catch(() => {
        this.isGoogleSubmitting = false;
        this.errorMessage = 'Não foi possível abrir o login com Google no momento.';
      });
  }

  protected submit(form: NgForm): void {
    if (this.isSubmitting || this.isGoogleSubmitting) {
      return;
    }

    if (form.invalid) {
      this.errorMessage = 'Preencha e-mail e senha para continuar.';
      return;
    }

    this.isSubmitting = true;
    this.errorMessage = null;

    const normalizedEmail = this.email.trim().toLowerCase();

    this.auth.login(normalizedEmail, this.password).subscribe({
      next: () => {
        this.isSubmitting = false;
        this.router.navigateByUrl('/dashboard');
      },
      error: (message: string) => {
        this.isSubmitting = false;
        this.errorMessage = message;
      },
    });
  }

  private getGoogleClientId(): string {
    return (
      window.CHECKOP_GOOGLE_CLIENT_ID ||
      environment.googleClientId ||
      document.querySelector<HTMLMetaElement>('meta[name="google-signin-client_id"]')?.content ||
      ''
    );
  }

  private loadGoogleScript(): Promise<void> {
    if (window.google?.accounts?.id) {
      return Promise.resolve();
    }

    if (this.googleScriptPromise) {
      return this.googleScriptPromise;
    }

    this.googleScriptPromise = new Promise((resolve, reject) => {
      const existingScript = document.getElementById(
        'google-gsi-script',
      ) as HTMLScriptElement | null;

      if (existingScript) {
        existingScript.addEventListener('load', () => resolve(), { once: true });
        existingScript.addEventListener(
          'error',
          () => reject(new Error('Google script failed to load')),
          {
            once: true,
          },
        );
        return;
      }

      const script = document.createElement('script');
      script.id = 'google-gsi-script';
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Google script failed to load'));
      document.head.appendChild(script);
    });

    return this.googleScriptPromise;
  }
}
