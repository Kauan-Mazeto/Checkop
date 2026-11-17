import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';

// Tipos mínimos do Google Identity Services (https://accounts.google.com/gsi/client).
interface GoogleCredentialResponse {
  credential?: string;
}

interface GoogleButtonOptions {
  type?: 'standard' | 'icon';
  theme?: 'outline' | 'filled_blue' | 'filled_black';
  size?: 'large' | 'medium' | 'small';
  text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
  shape?: 'rectangular' | 'pill' | 'circle' | 'square';
  logo_alignment?: 'left' | 'center';
  width?: number;
  locale?: string;
}

interface GoogleAccountsId {
  initialize(config: {
    client_id: string;
    callback: (response: GoogleCredentialResponse) => void;
    ux_mode?: 'popup' | 'redirect';
    auto_select?: boolean;
    cancel_on_tap_outside?: boolean;
  }): void;
  renderButton(parent: HTMLElement, options: GoogleButtonOptions): void;
  disableAutoSelect(): void;
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GoogleAccountsId } };
  }
}

export interface GoogleConfig {
  enabled: boolean;
  clientId: string | null;
}

const GSI_SCRIPT_URL = 'https://accounts.google.com/gsi/client';

/**
 * Login com Google pelo botão oficial (Google Identity Services).
 * O Google devolve um id_token (JWT assinado) e quem confere a assinatura, o
 * client id e o e-mail verificado é o backend (POST /api/auth/google).
 * O client id vem do próprio backend (GET /api/auth/google/config): o .env do
 * servidor é a fonte única, sem rebuild do front para trocar de projeto.
 */
@Injectable({ providedIn: 'root' })
export class GoogleAuthService {
  private readonly http = inject(HttpClient);

  private configPromise: Promise<GoogleConfig> | null = null;
  private scriptPromise: Promise<GoogleAccountsId> | null = null;

  /** Configuração do servidor; sem resposta, o botão simplesmente não aparece. */
  getConfig(): Promise<GoogleConfig> {
    this.configPromise ??= firstValueFrom(
      this.http.get<GoogleConfig>(`${API_BASE_URL}/auth/google/config`)
    ).catch(() => {
      this.configPromise = null; // tenta de novo na próxima tela
      return { enabled: false, clientId: null };
    });
    return this.configPromise;
  }

  /**
   * Desenha o botão oficial dentro de `parent`. `onCredential` recebe o
   * id_token quando o usuário escolhe a conta na janela do Google.
   */
  async renderButton(
    parent: HTMLElement,
    clientId: string,
    onCredential: (credential: string) => void,
    options: GoogleButtonOptions = {}
  ): Promise<void> {
    const gsi = await this.loadScript();
    gsi.initialize({
      client_id: clientId,
      callback: (response) => {
        if (response.credential) onCredential(response.credential);
      },
      ux_mode: 'popup',
      auto_select: false,
      cancel_on_tap_outside: true,
    });
    parent.replaceChildren();
    gsi.renderButton(parent, {
      type: 'standard',
      theme: 'filled_black',
      size: 'large',
      text: 'continue_with',
      shape: 'rectangular',
      logo_alignment: 'center',
      locale: 'pt-BR',
      // o botão do Google aceita de 200 a 400 px
      width: Math.max(200, Math.min(400, Math.floor(parent.clientWidth || 400))),
      ...options,
    });
  }

  /** Depois do logout, o Google não reentra sozinho na mesma conta. */
  disableAutoSelect(): void {
    window.google?.accounts?.id?.disableAutoSelect();
  }

  private loadScript(): Promise<GoogleAccountsId> {
    const ready = window.google?.accounts?.id;
    if (ready) return Promise.resolve(ready);

    this.scriptPromise ??= new Promise<GoogleAccountsId>((resolve, reject) => {
      const script = document.createElement('script');
      script.src = GSI_SCRIPT_URL;
      script.async = true;
      script.defer = true;
      script.onload = () => {
        const gsi = window.google?.accounts?.id;
        if (gsi) resolve(gsi);
        else reject(new Error('Google Identity Services indisponível.'));
      };
      script.onerror = () => {
        this.scriptPromise = null; // permite tentar de novo (ex.: rede voltou)
        script.remove();
        reject(new Error('Não foi possível carregar o login do Google.'));
      };
      document.head.appendChild(script);
    });
    return this.scriptPromise;
  }
}
