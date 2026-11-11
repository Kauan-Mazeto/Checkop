import { Routes } from '@angular/router';
import { landingPageRoute } from './pages/landing-page/landing-page.route';
import { loginPageRoute } from './pages/login-page/login-page.route';
import { registerPageRoute } from './pages/register-page/register-page.route';
import { initialPageRoute } from './pages/initial-page/initial-page.route';
import { dashboardPageRoute } from './pages/Dashboard-page/Dashboard-page.route';
import { targetsPageRoute } from './pages/targets-page/targets-page.route';
import { newScanPageRoute } from './pages/new-scan-page/new-scan-page.route';
import { scanDetailPageRoute } from './pages/scan-detail-page/scan-detail-page.route';
import { codeAnalysisPageRoute } from './pages/code-analysis-page/code-analysis-page.route';
import { scanHistoryPageRoute } from './pages/scan-history-page/scan-history-page.route';
import { accountPageRoute } from './pages/account-page/account-page.route';
import { privacyPageRoute, termsPageRoute } from './pages/legal-page/legal-page.route';
import { plansPageRoute } from './pages/plans-page/plans-page.route';

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
  dashboardPageRoute,
  targetsPageRoute,
  scanHistoryPageRoute,
  // 'scans/new' antes de 'scans/:id', senão "new" seria tratado como id
  newScanPageRoute,
  scanDetailPageRoute,
  codeAnalysisPageRoute,
  accountPageRoute,
  plansPageRoute,
  termsPageRoute,
  privacyPageRoute,
];
