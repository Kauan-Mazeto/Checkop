import { Injectable } from '@angular/core';

const PREFIX = 'checkop_draft:';

/**
 * Rascunho de formulário em sessionStorage: sobrevive a recarregar a página e
 * a voltar no navegador, e some ao fechar a aba. Nunca guarde senha aqui.
 * Toda leitura/escrita é protegida: em janela anônima ou com storage
 * bloqueado, o formulário só deixa de lembrar, sem quebrar.
 */
@Injectable({ providedIn: 'root' })
export class DraftService {
  load<T extends object>(key: string): Partial<T> {
    try {
      const raw = sessionStorage.getItem(PREFIX + key);
      return raw ? (JSON.parse(raw) as Partial<T>) : {};
    } catch {
      return {};
    }
  }

  save<T extends object>(key: string, value: T): void {
    try {
      sessionStorage.setItem(PREFIX + key, JSON.stringify(value));
    } catch {
      /* storage cheio ou bloqueado: ignora */
    }
  }

  clear(key: string): void {
    try {
      sessionStorage.removeItem(PREFIX + key);
    } catch {
      /* ignora */
    }
  }
}
