import { Injectable, signal } from '@angular/core';
import { DEFAULT_PLAN } from '../constants/dashboard.constants';
import type { ScanObjective } from './scan.service';

export type PlanTier = 'free' | 'premium';

export interface PlanFeature {
  label: string;
  included: boolean;
}

// O que cada plano libera. Os valores ficam em PLAN_DEFINITIONS
// (core/constants/dashboard.constants.ts); nenhum componente compara o nome do
// plano diretamente, todos leem estes campos — mudar uma regra de negócio é
// mexer num lugar só.
export interface PlanDefinition {
  id: PlanTier;
  name: string;
  priceLabel: string;
  // scans por dia; null = ilimitado
  dailyScanLimit: number | null;
  // false = o usuário não escolhe o tipo de teste: roda sempre `defaultObjective`
  canChooseObjective: boolean;
  defaultObjective: ScanObjective;
  // false = só enxerga o último scan, sem a lista de histórico
  canViewHistory: boolean;
  canExportReports: boolean;
  features: PlanFeature[];
}

@Injectable({ providedIn: 'root' })
export class PlanService {
  // BACKEND: o model User (backend/prisma/schema.prisma) ainda NÃO tem campo de
  // plano. Enquanto isso, todo mundo cai em DEFAULT_PLAN ('free'). Para
  // integrar:
  //   1. adicionar `plan` (enum FREE | PREMIUM) ao model User + migration;
  //   2. devolver `plan` em login, register, google e GET /api/auth/me — o
  //      applySession() abaixo já lê esse campo (aceita 'PREMIUM'/'premium');
  //   3. aplicar as regras TAMBÉM no servidor — o front só esconde/desabilita,
  //      quem garante é a API:
  //        - POST /api/scans: Free = 1 scan por dia e só o objetivo básico;
  //        - GET  /api/scans: Free = só o scan mais recente (sem histórico);
  //        - exportação de relatório: só Premium.
  // Para testar a visão Premium localmente, troque DEFAULT_PLAN para 'premium'.
  readonly plan = signal<PlanTier>(DEFAULT_PLAN);

  // Lê o plano de uma resposta de sessão (cache do login ou GET /auth/me).
  // Se o backend ainda não mandar `plan`, mantém o plano atual.
  applySession(session: unknown): void {
    const raw = (session as { plan?: unknown } | null)?.plan;

    if (typeof raw === 'string') {
      this.plan.set(raw.toLowerCase() === 'premium' ? 'premium' : 'free');
    }
  }
}
