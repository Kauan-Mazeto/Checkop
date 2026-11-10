import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

export const accountPageRoute: Route = {
  path: 'account',
  loadComponent: () => import('./account-page.component').then((m) => m.AccountPageComponent),
  canActivate: [authGuard],
};
