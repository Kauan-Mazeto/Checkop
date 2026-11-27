import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

// carregada sob demanda, como as outras telas logadas
export const aiHelpPageRoute: Route = {
  path: 'ai-help',
  loadComponent: () => import('./ai-help-page.component').then((m) => m.AiHelpPageComponent),
  canActivate: [authGuard],
};
