import { Routes } from '@angular/router';
import { landingPageRoute } from './pages/landing-page/landing-page.route';
import { loginPageRoute } from './pages/login-page/login-page.route';
import { registerPageRoute } from './pages/register-page/register-page.route';
import { initialPageRoute } from './pages/initial-page/initial-page.route';

export const routes: Routes = [
  {
    path: '',
    redirectTo: 'landing',
    pathMatch: 'full',
  },
  landingPageRoute,
  loginPageRoute,
  registerPageRoute,
  initialPageRoute,
];
