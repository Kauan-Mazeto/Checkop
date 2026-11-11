import { Route } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

// carregada sob demanda: o Chart.js e as telas logadas não entram no bundle da landing
export const newScanPageRoute: Route = {
  path: 'scans/new',
  loadComponent: () => import('./new-scan-page.component').then((m) => m.NewScanPageComponent),
  canActivate: [authGuard],
};
