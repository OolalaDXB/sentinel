/**
 * Cycle de vie d'un problème (schéma 002) : la règle que l'écran affiche et
 * que la base applique (`sentinel_set_issue_status`, `sentinel_ingest`).
 *
 * Non résolu → en cours → résolu / ignoré. Un résolu qui revient est une
 * RÉGRESSION : la base le repasse en non résolu, seule. Ignorer exige un
 * motif ; un ignoré compte ses événements mais n'alerte jamais.
 */

export type SentinelStatus = 'unresolved' | 'in_progress' | 'resolved' | 'ignored';

export const SENTINEL_STATUSES: readonly SentinelStatus[] = ['unresolved', 'in_progress', 'resolved', 'ignored'];

export type SentinelAlertKind = 'new_issue' | 'regression' | 'frequency';

export const SENTINEL_ALERT_KINDS: readonly SentinelAlertKind[] = ['new_issue', 'regression', 'frequency'];

/** Les gestes proposés depuis un statut : jamais le statut lui-même. */
export function nextStatuses(status: SentinelStatus): SentinelStatus[] {
  return SENTINEL_STATUSES.filter((s) => s !== status);
}

export function statusNeedsNote(status: SentinelStatus): boolean {
  return status === 'ignored';
}

/** Un problème « ouvert » demande un geste : non résolu ou en cours. */
export function isOpenStatus(status: SentinelStatus): boolean {
  return status === 'unresolved' || status === 'in_progress';
}
