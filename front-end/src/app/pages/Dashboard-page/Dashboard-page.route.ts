import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

// carregada sob demanda: o Chart.js e as telas logadas não entram no bundle da landing
export const dashboardPageRoute: Route = {
  path: 'dashboard',
  loadComponent: () => import('./Dashboard-page.component').then((m) => m.DashboardPageComponent),
  canActivate: [authGuard],
};
