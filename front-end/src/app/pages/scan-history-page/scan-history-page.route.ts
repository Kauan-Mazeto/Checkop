import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

export const scanHistoryPageRoute: Route = {
  path: 'scans',
  loadComponent: () => import('./scan-history-page.component').then((m) => m.ScanHistoryPageComponent),
  canActivate: [authGuard],
};
