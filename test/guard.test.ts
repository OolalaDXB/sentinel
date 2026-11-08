/**
 * Lot 5 : ce que le module guard accepte d'un garde de RLS. Paquet seul ;
 * le rapport est construit À LA MAIN au format `rls-guard-evidence/1`.
 */
import { describe, expect, it } from 'vitest';
import { GUARD_MAX_BYTES, invariantPassed, parseGuardSubmission } from '../src/modules/guard/index.ts';

const ev = (over: Record<string, unknown> = {}) => ({
  format: 'rls-guard-evidence/1', verdict: 'pass', commit_sha: 'a'.repeat(40),
  invariants: ['I1', 'I2', 'I3', 'I4'].map((id) => ({ id, title: id, status: 'pass', violations: [] }))
    .concat([{ id: 'STATE', title: 'STATE', status: 'not-run', violations: [] }]),
  exceptions: { in_effect: [], stale: [] }, ...over,
});
const sub = (exit: number, evidence?: unknown, run: Record<string, unknown> = {}) =>
  JSON.stringify({ run: { run_key: '42-1', exit_code: exit, run_url: 'https://github.com/o/r/actions/runs/42', event: 'pull_request', ...run }, ...(evidence === undefined ? {} : { evidence }) });

describe('ce que le module accepte', () => {
  it('un passage réussi, et un bloquant cohérent', () => {
    const ok = parseGuardSubmission(sub(0, ev()));
    expect(ok.ok && ok.run).toEqual({ run_key: '42-1', exit_code: 0, run_url: 'https://github.com/o/r/actions/runs/42', event: 'pull_request' });
    expect(parseGuardSubmission(sub(1, ev({ verdict: 'block' }))).ok).toBe(true);
  });
  it('une erreur (code 2) arrive SANS rapport, et en a un : refusée', () => {
    const e = parseGuardSubmission(sub(2));
    expect(e.ok && e.evidence).toBeNull();
    expect(parseGuardSubmission(sub(2, ev()))).toEqual({ ok: false, error: 'ERROR_RUN_HAS_EVIDENCE' });
  });
  it('format EXACT : ni /2, ni absent, ni approchant', () => {
    for (const format of ['rls-guard-evidence/2', 'rls-guard-evidence/1 ', 'RLS-GUARD-EVIDENCE/1', undefined]) {
      expect(parseGuardSubmission(sub(0, ev({ format })))).toEqual({ ok: false, error: 'FORMAT_INVALID' });
    }
    expect(parseGuardSubmission(sub(0))).toEqual({ ok: false, error: 'FORMAT_INVALID' });
  });
  it('verdict ni pass ni block : refusé ; code et verdict contradictoires : refusés', () => {
    expect(parseGuardSubmission(sub(0, ev({ verdict: 'warn' })))).toEqual({ ok: false, error: 'VERDICT_INVALID' });
    expect(parseGuardSubmission(sub(0, ev({ verdict: 'block' })))).toEqual({ ok: false, error: 'VERDICT_EXIT_MISMATCH' });
    expect(parseGuardSubmission(sub(1, ev()))).toEqual({ ok: false, error: 'VERDICT_EXIT_MISMATCH' });
  });
  it('invariant inconnu ou statut hors liste : refusé', () => {
    expect(parseGuardSubmission(sub(0, ev({ invariants: [{ id: 'I9', status: 'pass', violations: [] }] }))).ok).toBe(false);
    expect(parseGuardSubmission(sub(0, ev({ invariants: [{ id: 'I1', status: 'skipped', violations: [] }] }))).ok).toBe(false);
  });
  it('plus de 2 Mo, pas du JSON, passage sans clé ou code hors liste : refusés', () => {
    expect(parseGuardSubmission('x'.repeat(GUARD_MAX_BYTES + 1))).toEqual({ ok: false, error: 'BODY_TOO_LARGE' });
    expect(parseGuardSubmission('{nope')).toEqual({ ok: false, error: 'NOT_JSON' });
    expect(parseGuardSubmission(sub(0, ev(), { run_key: '' }))).toEqual({ ok: false, error: 'RUN_INVALID' });
    expect(parseGuardSubmission(sub(3, ev()))).toEqual({ ok: false, error: 'RUN_INVALID' });
  });
  it('une adresse de passage qui n’est pas https est oubliée, pas crue', () => {
    const r = parseGuardSubmission(sub(0, ev(), { run_url: 'javascript:alert(1)' }));
    expect(r.ok && r.run.run_url).toBeNull();
  });
  it('« non exécuté » n’est jamais un succès', () => {
    expect(invariantPassed('pass')).toBe(true);
    expect(invariantPassed('not-run')).toBe(false);
    expect(invariantPassed(undefined)).toBe(false);
  });
});
