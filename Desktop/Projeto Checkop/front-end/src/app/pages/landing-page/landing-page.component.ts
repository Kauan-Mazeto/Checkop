import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

type AppView = 'landing' | 'dashboard';
type DashboardTab = 'overview' | 'scans' | 'reports' | 'logs';

interface ScanVulnerability {
  type: string;
  path: string;
  severity: 'critical' | 'medium';
  fix: string;
}

@Component({
  selector: 'app-shieldtest',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './landing-page.component.html',
  styleUrl: './landing-page.component.scss',
})
export class LandingPageComponent {
  protected readonly appName = 'ShieldTest';

  protected currentView: AppView = 'landing';
  protected dashboardTab: DashboardTab = 'overview';

  protected isNewScanModalOpen = false;
  protected isScanning = false;

  protected selectedRole: string | null = null;
  protected scanUrl = '';
  protected scanResult: {
    environment: 'DEV' | 'PROD';
    vulnerabilities: ScanVulnerability[];
    passes: string[];
  } | null = null;

  protected readonly roles = [
    { id: 'qa', label: '🧪 QA' },
    { id: 'dev', label: '💻 Dev' },
    { id: 'pentester', label: '🔓 Pentester' },
    { id: 'student', label: '📚 Estudante' },
  ];

  protected readonly recentScans = [
    {
      url: 'meuapp.com',
      environment: 'PROD',
      status: '2 críticas',
      statusType: 'critical',
      vulnerabilities: 'SQLi, XSS',
      date: 'Hoje',
    },
    {
      url: 'api.staging.io',
      environment: 'DEV',
      status: 'Seguro',
      statusType: 'safe',
      vulnerabilities: '—',
      date: 'Ontem',
    },
    {
      url: 'loja.dev.local',
      environment: 'DEV',
      status: '1 média',
      statusType: 'medium',
      vulnerabilities: 'CORS',
      date: '3 dias',
    },
  ];

  protected readonly logLines = [
    '[2025-01-15 14:32:01] Initiating scan on meuapp.com',
    '[2025-01-15 14:32:01] Detecting environment... PROD',
    '[2025-01-15 14:32:02] Testing vector: SQL Injection',
    "[2025-01-15 14:32:02] VULN FOUND: SQLi @ /api/users?id=1' OR '1'='1",
    "[2025-01-15 14:32:02] → Payload: ' UNION SELECT null,email,password FROM users--",
    '[2025-01-15 14:32:03] Testing vector: XSS (Reflected)',
    '[2025-01-15 14:32:03] VULN FOUND: XSS @ /search?q=<script>alert(1)</script>',
    '[2025-01-15 14:32:04] PASS: CSRF tokens validated',
    '[2025-01-15 14:32:04] PASS: Security headers present',
    '[2025-01-15 14:32:04] PASS: HTTPS enforced with HSTS',
    '[2025-01-15 14:32:05] Scan complete: 2 critical, 0 medium, 12 passed',
  ];

  protected navigateTo(view: AppView): void {
    this.currentView = view;

    if (view === 'dashboard') {
      this.dashboardTab = 'overview';
    }
  }

  protected selectRole(role: string): void {
    this.selectedRole = role;
  }

  protected switchDashboardTab(tab: DashboardTab): void {
    this.dashboardTab = tab;
  }

  protected openNewScan(): void {
    this.isNewScanModalOpen = true;
  }

  protected closeNewScan(): void {
    this.isNewScanModalOpen = false;
  }

  protected startScanFromModal(): void {
    this.isNewScanModalOpen = false;
    this.dashboardTab = 'scans';

    setTimeout(() => {
      document.querySelector<HTMLInputElement>('#scan-url')?.focus();
    });
  }

  protected runScan(): void {
    if (!this.scanUrl.trim() || this.isScanning) {
      return;
    }

    this.isScanning = true;
    this.scanResult = null;

    setTimeout(() => {
      const isDevelopment = /localhost|dev|staging|127\.0\.0\.1|\.local/i.test(this.scanUrl);

      this.scanResult = {
        environment: isDevelopment ? 'DEV' : 'PROD',
        vulnerabilities: [
          {
            type: 'SQL Injection',
            path: '/api/users',
            severity: 'critical',
            fix: 'Use consultas parametrizadas',
          },
          {
            type: 'XSS refletido',
            path: '/search?q=',
            severity: 'critical',
            fix: 'Sanitize os dados e use CSP',
          },
        ],
        passes: ['CSRF Tokens', 'Security Headers', 'HTTPS/HSTS', 'Rate Limiting'],
      };

      this.isScanning = false;
    }, 1800);
  }

  protected downloadReport(name: string): void {
    const content = [
      'ShieldTest - Relatório de Segurança',
      '='.repeat(40),
      `Aplicação: ${name}`,
      `Data: ${new Date().toLocaleDateString('pt-BR')}`,
      '',
      '[DEMO] Este é um relatório de exemplo.',
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = `shieldtest-${name}-report.txt`;
    anchor.click();

    URL.revokeObjectURL(url);
  }

  protected trackById(_: number, item: { id: string }): string {
    return item.id;
  }

  protected trackByText(_: number, item: string): string {
    return item;
  }
}
