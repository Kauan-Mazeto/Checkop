import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

// carregada sob demanda: o Chart.js e as telas logadas não entram no bundle da landing
export const targetsPageRoute: Route = {
  path: 'targets',
  loadComponent: () => import('./targets-page.component').then((m) => m.TargetsPageComponent),
  canActivate: [authGuard],
};
