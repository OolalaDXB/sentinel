import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  createSentinel, fingerprintOf, normalizeError, scrubText, scrubUrl, validateEvent,
  withSentinel, SENTINEL_LIMITS, type SentinelEvent, isOpenStatus, nextStatuses, statusNeedsNote,
} from '../src/index.ts';

const root = resolve(__dirname, '..');
const read = (p: string) => readFileSync(resolve(root, p), 'utf8');
const code = (p: string) => read(p).replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('Sentinel', () => {
  it('une erreur Supabase garde message, code, détail et indice — jamais « [object Object] »', () => {
    const n = normalizeError({ message: 'new row violates row-level security policy', code: '42501', details: null, hint: 'vérifiez le rôle' });
    expect(n).toMatchObject({ type: 'permission_denied', code: '42501', hint: 'vérifiez le rôle' });
    const bare = normalizeError({ foo: 1, bar: 'x' });
    expect(bare.message).not.toMatch(/\[object Object\]/);
    expect(bare.message).toMatch(/foo: number/);
    expect(normalizeError({ error: { message: 'imbriquée' } }).message).toBe('imbriquée');
    expect(normalizeError(null).message).toBeTruthy();
    expect(normalizeError({ code: 'PGRST116', message: 'x' }).type).toBe('database');
    expect(normalizeError(new TypeError('a.b is undefined')).type).toBe('javascript');
  });

  it('rien de secret ne sort : e-mail, JWT, clé, requête et fragment', () => {
    const jwt = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'abcdefghijklmnopqrstuvwxyz012345'].join('.');
    const clean = scrubText(`refus pour jean@shop.fr avec ${jwt} et sb_secret_abcdefghij1234 et Bearer abcdefgh12345678`);
    expect(clean).not.toMatch(/jean@shop\.fr|eyJ|sb_secret_abc|abcdefgh12345678/);
    expect(scrubUrl('https://pro.x/t/a/pro?produit=1#access_token=SECRET&type=magiclink')).toBe('https://pro.x/t/a/pro');
    expect(scrubText('https://x/cb?access_token=abc123&ok=1')).toBe('https://x/cb?access_token=[secret]&ok=1');
  });

  it('empreinte : chiffres neutralisés, deux appelants séparés, fichier haché ignoré', () => {
    expect(fingerprintOf(normalizeError('Slow operation: products took 37261ms')))
      .toBe(fingerprintOf(normalizeError('Slow operation: products took 12840ms')));
    const withStack = (stack: string) => normalizeError(Object.assign(new Error('boom'), { stack }));
    const s1 = withStack('Error: boom\n    at loadOrders (https://x/assets/index-a1.js:1:2)\n    at run (https://x/assets/index-a1.js:3:4)');
    const s2 = withStack('Error: boom\n    at saveInvoice (https://x/assets/index-b2.js:9:9)');
    const s1b = withStack('Error: boom\n    at loadOrders (https://x/assets/index-ZZ.js:7:8)\n    at run (https://x/assets/index-ZZ.js:1:1)');
    expect(fingerprintOf(s1)).not.toBe(fingerprintOf(s2));
    expect(fingerprintOf(s1b)).toBe(fingerprintOf(s1));
  });

  it('le serveur ne croit rien : plafond, format, empreinte et type recalculés, heure du serveur', () => {
    expect(validateEvent('x'.repeat(SENTINEL_LIMITS.body + 1))).toEqual({ ok: false, reason: 'BODY_TOO_LARGE' });
    expect(validateEvent('{nope')).toEqual({ ok: false, reason: 'NOT_JSON' });
    expect(validateEvent(JSON.stringify({ v: 2, error: { message: 'x' } }))).toEqual({ ok: false, reason: 'BAD_VERSION' });
    const forged = {
      v: 1, fingerprint: 'choisie-par-le-client', occurred_at: '2001-01-01T00:00:00Z', surface: 'erp',
      error: { type: 'render', message: 'refus jean@shop.fr', code: '42501' },
      url: 'https://x/p?token=abc#access_token=zzz', claimed_tenant: 'pas-un-uuid',
      breadcrumbs: [{ at: '2026-11-07T10:00:00Z', category: 'navigation', message: 'https://x/a?b=c' }],
      context: { k: 'v' },
    };
    const now = new Date('2026-11-07T12:00:00Z');
    const r = validateEvent(JSON.stringify(forged), now);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.event.fingerprint).toBe(fingerprintOf(r.event.error));
    expect(r.event.error.type).toBe('permission_denied');
    expect(r.event.error.message).not.toMatch(/jean@shop\.fr/);
    expect(r.event.url).toBe('https://x/p');
    expect(r.event.claimed_tenant).toBeNull();
    expect(r.event.occurred_at).toBe(now.toISOString());
    expect(r.event.breadcrumbs[0].message).toBe('https://x/a');
  });

  it('SDK : ne répète pas, plafonne, écarte les fragments périmés, ne lève jamais', async () => {
    const sent: SentinelEvent[] = [];
    let t = 0;
    const tick = () => new Promise((r) => setTimeout(r, 0));
    const s = createSentinel({ endpoint: 'x', transport: (e) => { sent.push(e); }, now: () => t, maxPerMinute: 3 });
    s.captureException(new Error('même'));
    s.captureException(new Error('même'));
    await tick();
    expect(sent.length).toBe(1);
    s.captureException(new Error('Failed to fetch dynamically imported module: /assets/x.js'));
    await tick();
    expect(sent.length).toBe(1);
    for (let i = 0; i < 10; i++) s.captureException(new Error(`différente ${'x'.repeat(i)}`));
    await tick();
    expect(sent.length).toBe(3);
    t = 61_000;
    s.captureException(new Error('après la minute'));
    await tick();
    expect(sent.length).toBe(4);
    const broken = createSentinel({ endpoint: 'x', transport: () => { throw new Error('panne'); } });
    expect(() => broken.captureException(new Error('y'))).not.toThrow();
  });

  it('SDK Deno : une erreur levée devient un événement « edge » et un 500 sans détail', async () => {
    const written: SentinelEvent[] = [];
    const h = withSentinel(async () => { throw Object.assign(new Error('relation "x" does not exist'), { code: '42P01' }); },
      { functionName: 'demo', write: async (e) => { written.push(e); } });
    const res = await h(new Request('https://f/functions/v1/demo?secret=1'));
    expect(res.status).toBe(500);
    expect(await res.text()).not.toMatch(/relation/);
    expect(written[0]).toMatchObject({ surface: 'edge', url: '/functions/v1/demo', context: { function: 'demo' } });
  });

  it('le paquet ne connaît aucun hôte, et son schéma ne supprime rien', () => {
    for (const f of readdirSync(resolve(root, 'src'))) {
      expect(code(`src/${f}`), f).not.toMatch(/supabase|tenant_users|from\s+['"]@\/|sillon/i);
    }
    expect(read('sql/001_sentinel.sql')).not.toMatch(/\b(drop|delete|truncate)\b/i);
    const v2 = read('sql/002_lifecycle.sql');
    const purge = v2.indexOf('FUNCTION public.sentinel_purge(');
    expect(v2.slice(0, purge)).not.toMatch(/\b(drop|delete|truncate)\b/i);
    expect(v2.slice(purge).match(/\bDELETE FROM\b/g)?.length).toBe(2);
  });

  it('cycle de vie : jamais le statut lui-même, ignorer exige un motif', () => {
    expect(nextStatuses('resolved')).toEqual(['unresolved', 'in_progress', 'ignored']);
    expect(statusNeedsNote('ignored')).toBe(true);
    expect(statusNeedsNote('in_progress')).toBe(false);
    expect(isOpenStatus('in_progress')).toBe(true);
    expect(isOpenStatus('resolved')).toBe(false);
  });
});
