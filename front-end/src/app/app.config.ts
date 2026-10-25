import {
  ApplicationConfig,
  provideBrowserGlobalErrorListeners,
  provideZoneChangeDetection,
} from '@angular/core';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { provideRouter } from '@angular/router';

import { environment } from '../environments/environment';
import { routes } from './app.routes';

if (typeof window !== 'undefined') {
  (window as Window & { GOOGLE_CLIENT_ID?: string }).GOOGLE_CLIENT_ID = environment.googleClientId;

  const meta = document.querySelector<HTMLMetaElement>('meta[name="google-signin-client_id"]');
  if (meta && environment.googleClientId) {
    meta.content = environment.googleClientId;
  }
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideHttpClient(withFetch()),
  ],
};
