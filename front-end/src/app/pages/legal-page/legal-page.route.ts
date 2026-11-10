import { Route } from '@angular/router';

// públicas: precisam abrir antes do cadastro e do login
export const termsPageRoute: Route = {
  path: 'terms',
  loadComponent: () => import('./legal-page.component').then((m) => m.LegalPageComponent),
  data: { doc: 'terms' },
};

export const privacyPageRoute: Route = {
  path: 'privacy',
  loadComponent: () => import('./legal-page.component').then((m) => m.LegalPageComponent),
  data: { doc: 'privacy' },
};
