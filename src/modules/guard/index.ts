/**
 * Module « guard » (schéma modules/guard/001) : ce que Sentinel accepte d'un
 * garde de RLS. Le module ne connaît qu'un FORMAT de sortie,
 * `rls-guard-evidence/1` ; il n'importe rien de l'outil qui le produit.
 *
 * Un envoi : `{ run: { run_key, exit_code, run_url?, event? }, evidence? }`.
 *   - code 2 (erreur) : AUCUN rapport — l'envoi l'inscrit `error`, jamais pass ;
 *   - code 0 / 1 : le rapport, au format EXACT, verdict pass | block, et le
 *     code qui dit la même chose que le verdict.
 * La base revérifie tout (`sentinel_guard_ingest`) : ce contrôle refuse tôt,
 * il ne décide pas seul.
 */

export const GUARD_FORMAT = 'rls-guard-evidence/1';
export const GUARD_MAX_BYTES = 2 * 1024 * 1024;

export type GuardInvariantId = 'I1' | 'I2' | 'I3' | 'I4' | 'STATE';
export const GUARD_INVARIANT_IDS: readonly GuardInvariantId[] = ['I1', 'I2', 'I3', 'I4', 'STATE'];

/** `not-run` n'est jamais un succès : STATE sans référence le rend. */
export type GuardInvariantStatus = 'pass' | 'fail' | 'not-run';
export const GUARD_INVARIANT_STATUSES: readonly GuardInvariantStatus[] = ['pass', 'fail', 'not-run'];

export type GuardRunStatus = 'pass' | 'block' | 'error';
export const GUARD_RUN_STATUSES: readonly GuardRunStatus[] = ['pass', 'block', 'error'];

export interface GuardRunMeta {
  run_key: string;
  exit_code: 0 | 1 | 2;
  run_url: string | null;
  event: string | null;
}

export type GuardSubmissionError =
  | 'BODY_TOO_LARGE' | 'NOT_JSON' | 'RUN_INVALID' | 'FORMAT_INVALID' | 'VERDICT_INVALID'
  | 'VERDICT_EXIT_MISMATCH' | 'ERROR_RUN_HAS_EVIDENCE' | 'INVARIANTS_INVALID';

export type GuardSubmission =
  | { ok: true; run: GuardRunMeta; evidence: Record<string, unknown> | null }
  | { ok: false; error: GuardSubmissionError };

const RUN_URL = /^https:\/\/[^\s]{1,490}$/;

export function parseGuardSubmission(raw: string): GuardSubmission {
  if (new TextEncoder().encode(raw).length > GUARD_MAX_BYTES) return { ok: false, error: 'BODY_TOO_LARGE' };
  let body: Record<string, unknown>;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, error: 'NOT_JSON' };
    body = parsed as Record<string, unknown>;
  } catch {
    return { ok: false, error: 'NOT_JSON' };
  }
  const run = body.run as Record<string, unknown> | undefined;
  const exit = run?.exit_code;
  const key = typeof run?.run_key === 'string' ? run.run_key.trim() : '';
  if (!run || typeof run !== 'object' || !key || key.length > 120 || (exit !== 0 && exit !== 1 && exit !== 2)) {
    return { ok: false, error: 'RUN_INVALID' };
  }
  const meta: GuardRunMeta = {
    run_key: key,
    exit_code: exit,
    run_url: typeof run.run_url === 'string' && RUN_URL.test(run.run_url) ? run.run_url : null,
    event: typeof run.event === 'string' ? run.event.slice(0, 40) : null,
  };
  const evidence = body.evidence;
  if (exit === 2) {
    // Une erreur n'a pas de rapport : en recevoir un est une contradiction.
    if (evidence !== undefined && evidence !== null) return { ok: false, error: 'ERROR_RUN_HAS_EVIDENCE' };
    return { ok: true, run: meta, evidence: null };
  }
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return { ok: false, error: 'FORMAT_INVALID' };
  const ev = evidence as Record<string, unknown>;
  if (ev.format !== GUARD_FORMAT) return { ok: false, error: 'FORMAT_INVALID' };
  if (ev.verdict !== 'pass' && ev.verdict !== 'block') return { ok: false, error: 'VERDICT_INVALID' };
  if ((exit === 0) !== (ev.verdict === 'pass')) return { ok: false, error: 'VERDICT_EXIT_MISMATCH' };
  if (!Array.isArray(ev.invariants)) return { ok: false, error: 'INVARIANTS_INVALID' };
  for (const inv of ev.invariants as Array<Record<string, unknown>>) {
    if (!inv || !GUARD_INVARIANT_IDS.includes(inv.id as GuardInvariantId)
      || !GUARD_INVARIANT_STATUSES.includes(inv.status as GuardInvariantStatus)
      || !Array.isArray(inv.violations)) return { ok: false, error: 'INVARIANTS_INVALID' };
  }
  return { ok: true, run: meta, evidence: ev };
}

/** Un statut d'invariant ne compte comme réussi que s'il dit « pass ». */
export function invariantPassed(status: GuardInvariantStatus | null | undefined): boolean {
  return status === 'pass';
}
