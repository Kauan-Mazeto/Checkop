import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

export const plansPageRoute: Route = {
  path: 'plans',
  loadComponent: () => import('./plans-page.component').then((m) => m.PlansPageComponent),
  canActivate: [authGuard],
};
