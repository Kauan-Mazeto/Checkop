import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

// carregada sob demanda: o Chart.js e as telas logadas não entram no bundle da landing
export const codeAnalysisPageRoute: Route = {
  path: 'code-analysis',
  loadComponent: () => import('./code-analysis-page.component').then((m) => m.CodeAnalysisPageComponent),
  canActivate: [authGuard],
};
