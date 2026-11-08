/**
 * Module « moniteurs » (schéma modules/monitors/001) : la règle qu'applique
 * la base (`sentinel_monitor_state`), recopiée pour l'écran et les tests.
 * Elle ne lit que des PREUVES de passage, jamais la tâche elle-même.
 */

export type MonitorState = 'unknown' | 'ok' | 'late' | 'failed';

export const MONITOR_STATES: readonly MonitorState[] = ['unknown', 'ok', 'late', 'failed'];

/** Type d'un problème ouvert par un moniteur ; `monitor_drill` est l'exercice. */
export type MonitorIssueKind = 'monitor_missed' | 'monitor_failed' | 'monitor_drill';

export interface MonitorProof {
  expectedEveryMinutes: number | null;
  toleranceMinutes: number | null;
  lastSuccessAt: Date | null;
  lastFailureAt: Date | null;
}

export function evaluateMonitor(p: MonitorProof, now: Date): MonitorState {
  if (p.lastFailureAt && (!p.lastSuccessAt || p.lastFailureAt.getTime() > p.lastSuccessAt.getTime())) return 'failed';
  if (!p.lastSuccessAt || p.expectedEveryMinutes == null) return 'unknown';
  const limit = (p.expectedEveryMinutes + (p.toleranceMinutes ?? 0)) * 60_000;
  return now.getTime() - p.lastSuccessAt.getTime() > limit ? 'late' : 'ok';
}

/** Tolérance par défaut : la moitié de la planification, deux heures de marge au moins. */
export function defaultTolerance(expectedEveryMinutes: number | null): number | null {
  if (expectedEveryMinutes == null) return null;
  return Math.min(10080, Math.max(Math.ceil(expectedEveryMinutes * 0.5), 120 - expectedEveryMinutes, 0));
}

/** Empreinte du problème d'un moniteur : `<type>:<nom>`, celle que pose la base. */
export function monitorFingerprint(kind: MonitorIssueKind, name: string): string {
  return `${kind}:${name}`;
}

/** Un moniteur qui n'a jamais rougi n'a peut-être jamais rien mesuré. */
export function isProven(m: { everRedAt: string | null; lastDrillDispatched: boolean | null }): boolean {
  return m.everRedAt != null || m.lastDrillDispatched === true;
}
