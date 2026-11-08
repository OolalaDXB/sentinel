/**
 * Santé des versions (schéma 006) : un battement de session LÉGER et
 * ANONYME. Une session compte une fois (« start ») et, si une erreur non
 * attrapée remonte, une fois « crashed ». Rien ne part qui désigne la
 * personne ni la session : la base ne garde que des compteurs par version.
 *
 * « Une fois » se garde dans le stockage de session du navigateur, par
 * version : un rechargement ne recompte pas, un nouvel onglet si. Rien ne
 * lève, rien n'est attendu.
 */
import type { SentinelSurface } from './types.ts';

export type SessionStatus = 'start' | 'crashed';

export interface SessionBeat {
  type: 'session';
  release: string | null;
  surface: SentinelSurface;
  status: SessionStatus;
}

export interface SessionHealthOptions {
  release: string | null;
  surface: () => SentinelSurface;
  send: (beat: SessionBeat) => unknown;
  /** `sessionStorage` ; absent ou en panne : un battement par chargement. */
  storage?: Pick<Storage, 'getItem' | 'setItem'> | null;
}

export interface SessionHealth {
  start(): boolean;
  crashed(): boolean;
}

export function createSessionHealth(options: SessionHealthOptions): SessionHealth {
  const memory = new Set<string>();
  const once = (status: SessionStatus): boolean => {
    const key = `sentinel:session:${status}:${options.release ?? ''}`;
    try {
      if (memory.has(key)) return false;
      try {
        if (options.storage?.getItem(key)) { memory.add(key); return false; }
        options.storage?.setItem(key, '1');
      } catch { /* stockage refusé : la mémoire suffit */ }
      memory.add(key);
      void Promise.resolve()
        .then(() => options.send({ type: 'session', release: options.release, surface: options.surface(), status }))
        .catch(() => undefined);
      return true;
    } catch {
      return false;
    }
  };
  return {
    start: () => once('start'),
    // Une session plantée a forcément commencé : sans « start », la base
    // compterait plus de plantées que de sessions.
    crashed: () => { once('start'); return once('crashed'); },
  };
}
