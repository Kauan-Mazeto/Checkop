import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';

export interface TeamProject {
  id: string;
  name: string;
}

export interface TeamMember {
  id: string;
  name: string;
  role: 'owner' | 'admin' | 'member';
}

export interface TeamOverview {
  currentProjectId: string;
  projects: TeamProject[];
  members: TeamMember[];
  memberLimit: number;
  aggregatedScans: number;
}

// Dados de exemplo — recurso exclusivo do plano Business.
const MOCK_OVERVIEW: TeamOverview = {
  currentProjectId: 'p1',
  projects: [
    { id: 'p1', name: 'Projeto principal' },
    { id: 'p2', name: 'Portal interno' },
  ],
  members: [
    { id: 'm1', name: 'Membro 1', role: 'owner' },
    { id: 'm2', name: 'Membro 2', role: 'admin' },
    { id: 'm3', name: 'Membro 3', role: 'member' },
  ],
  memberLimit: 5,
  aggregatedScans: 12,
};

@Injectable({ providedIn: 'root' })
export class TeamService {
  // BACKEND (ainda não existe no servidor): trocar o `of(...)` por
  //   GET  /api/team/overview     -> TeamOverview
  //   POST /api/team/members      -> convidar/remover membros
  //   GET  /api/team/permissions  -> permissões por membro
  // mantendo o retorno Observable<TeamOverview>, o componente não precisa mudar.
  getOverview(): Observable<TeamOverview> {
    return of(MOCK_OVERVIEW);
  }
}
