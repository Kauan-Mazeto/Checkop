import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

// carregada sob demanda: o Chart.js e as telas logadas não entram no bundle da landing
export const scanDetailPageRoute: Route = {
  path: 'scans/:id',
  loadComponent: () => import('./scan-detail-page.component').then((m) => m.ScanDetailPageComponent),
  canActivate: [authGuard],
};
