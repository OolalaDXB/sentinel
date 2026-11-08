/**
 * Module « uptime » (schéma modules/uptime/001) : la règle qu'applique la
 * base, recopiée pour l'écran et les tests. La preuve est la RÉPONSE.
 */

export type UptimeState = 'unknown' | 'up' | 'down';
export const UPTIME_STATES: readonly UptimeState[] = ['unknown', 'up', 'down'];

/** Un statut attendu s'il y en a, sinon 2xx ou 3xx ; un délai dépassé n'est jamais sain. */
export function isHealthyStatus(status: number | null | undefined, expected: number[] | null | undefined, timedOut = false): boolean {
  if (timedOut || status == null || status <= 0) return false;
  if (expected && expected.length) return expected.includes(status);
  return status >= 200 && status <= 399;
}

/** Échecs D'AFFILÉE, du plus récent au dernier succès. `checks` : plus récent d'abord. */
export function consecutiveFailures(checks: Array<{ healthy: boolean | null }>): number {
  let n = 0;
  for (const c of checks) {
    if (c.healthy === null) continue;
    if (c.healthy) break;
    n += 1;
  }
  return n;
}

/** Disponibilité sur une période : sains ÷ vérifiés, null sans vérification (jamais 100 % inventés). */
export function availability(healthy: number, checked: number): number | null {
  return checked > 0 ? healthy / checked : null;
}
