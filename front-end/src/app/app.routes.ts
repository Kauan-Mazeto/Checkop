import { Routes } from '@angular/router';
import { landingPageRoute } from './pages/landing-page/landing-page.component.route';

export const routes: Routes = [
  { path: '', redirectTo: 'landing', pathMatch: 'full' },
  landingPageRoute,
];
