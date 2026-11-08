/**
 * Lot 2 : refus de données, enrobage Deno non intrusif, moniteurs.
 * Tests du paquet SEUL : imports relatifs, aucun module de l'hôte.
 */
import { describe, expect, it, vi } from 'vitest';
import { buildEvent, validateEvent } from '../src/event.ts';
import { cleanDataFailure, dataFailureError, redactValues } from '../src/data.ts';
import { createSentinel } from '../src/browser.ts';
import { must, withSentinel, type DenoCaptureOptions } from '../src/deno.ts';
import { SENTINEL_NO_ROWS_CODE, type SentinelEvent } from '../src/types.ts';
import { defaultTolerance, evaluateMonitor, isProven } from '../src/modules/monitors/index.ts';

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('refus de données : objet + opération + code, sans valeurs', () => {
  const ev = (msg: string, resource = 'widgets', operation = 'insert', code = '42501') => {
    const b = dataFailureError({ resource, operation, status: 403, code, message: msg })!;
    return buildEvent({ error: b.error, data: b.data });
  };

  it('deux lignes refusées de la même table : même empreinte', () => {
    expect(ev('new row violates row-level security policy for table "widgets" (id 12)').fingerprint)
      .toBe(ev('autre message, autre ligne 99').fingerprint);
  });

  it('un autre objet, une autre opération, un autre code : une autre empreinte', () => {
    const base = ev('x').fingerprint;
    expect(ev('x', 'gadgets').fingerprint).not.toBe(base);
    expect(ev('x', 'widgets', 'update').fingerprint).not.toBe(base);
    expect(ev('x', 'widgets', 'insert', '23505').fingerprint).not.toBe(base);
  });

  it('les valeurs recopiées par la base ne sortent pas ; le nom de l’objet reste', () => {
    const m = redactValues('duplicate key value violates unique constraint "gadgets_email_key" Key (email)=(jean@shop.fr)');
    expect(m).not.toMatch(/jean@shop/);
    expect(m).toMatch(/gadgets_email_key/);
    expect(redactValues('invalid input syntax for type uuid: "abc-123"')).not.toMatch(/abc-123/);
    const e = ev('Key (email)=(jean@shop.fr) already exists');
    expect(JSON.stringify(e)).not.toMatch(/jean@shop/);
    expect(e.error.details).toBeNull();
  });

  it('42501 reste un refus de droits ; le reste devient une erreur de base', () => {
    expect(ev('x').error.type).toBe('permission_denied');
    expect(ev('x', 'widgets', 'insert', '23505').error.type).toBe('database');
    expect(ev('x', 'widgets', 'update', SENTINEL_NO_ROWS_CODE).error.type).toBe('database');
  });

  it('l’objet et l’opération entrent dans le contexte gardé par la base', () => {
    expect(ev('x').context).toMatchObject({ resource: 'widgets', operation: 'insert', status: 403 });
  });

  it('forme refusée : objet qui n’est pas un identifiant, opération hors liste', () => {
    expect(cleanDataFailure({ resource: 'widgets; select 1', operation: 'insert' })).toBeNull();
    expect(cleanDataFailure({ resource: 'widgets', operation: 'truncate' })).toBeNull();
    expect(cleanDataFailure({ resource: 'public.Widgets', operation: 'UPDATE', status: 403 })).toEqual({ resource: 'widgets', operation: 'update', status: 403 });
  });

  it('le serveur recalcule l’empreinte depuis l’objet, jamais celle du client', () => {
    const real = ev('x');
    const forged = { ...real, fingerprint: 'choisie' };
    const r = validateEvent(JSON.stringify(forged));
    expect(r.ok && r.event.fingerprint).toBe(real.fingerprint);
    const noData = validateEvent(JSON.stringify({ ...real, data: undefined }));
    expect(noData.ok && noData.event.fingerprint).not.toBe(real.fingerprint);
  });

  it('SDK navigateur : captureDataFailure passe par le même dédoublonnage et ne lève jamais', async () => {
    const sent: SentinelEvent[] = [];
    const s = createSentinel({ endpoint: 'x', transport: (e) => { sent.push(e); }, now: () => 1000 });
    expect(s.captureDataFailure({ resource: 'widgets', operation: 'insert', status: 403, code: '42501' })).not.toBeNull();
    expect(s.captureDataFailure({ resource: 'widgets', operation: 'insert', status: 403, code: '42501' })).toBeNull();
    await flush();
    expect(sent).toHaveLength(1);
    expect(s.captureDataFailure({ resource: 'pas un nom!', operation: 'insert' })).toBeNull();
    const broken = createSentinel({ endpoint: 'x', transport: () => { throw new Error('panne'); } });
    expect(() => broken.captureDataFailure({ resource: 'widgets', operation: 'update', code: '42501' })).not.toThrow();
  });
});

describe('withSentinel : observer sans jamais changer', () => {
  const opts = (over: Partial<DenoCaptureOptions> = {}): DenoCaptureOptions & { events: SentinelEvent[] } => {
    const events: SentinelEvent[] = [];
    return { functionName: 'f', write: async (e: SentinelEvent) => { events.push(e); }, events, ...over } as never;
  };

  it('éteint : le gestionnaire LUI-MÊME est rendu', () => {
    const h = async () => new Response('ok');
    expect(withSentinel(h, opts({ enabled: false }))).toBe(h);
    expect(withSentinel(h, opts({ enabled: () => false }))).toBe(h);
    expect(withSentinel(h, opts({ enabled: () => { throw new Error('x'); } }))).toBe(h);
  });

  it('réponse ≥ 500 : même objet rendu, corps intact, un événement', async () => {
    const o = opts();
    const original = new Response('secret du corps', { status: 503, headers: { 'X-B': '1' } });
    const res = await withSentinel(async () => original, o)(new Request('https://e/functions/v1/f?token=z'));
    expect(res).toBe(original);
    expect(await res.text()).toBe('secret du corps');
    await flush();
    expect(o.events).toHaveLength(1);
    expect(o.events[0].error.type).toBe('edge_function');
    expect(JSON.stringify(o.events)).not.toMatch(/secret du corps|token=z/);
  });

  it('réponse < 500 : rien', async () => {
    const o = opts();
    await withSentinel(async () => new Response('', { status: 403 }), o)(new Request('https://e/f'));
    await flush();
    expect(o.events).toHaveLength(0);
  });

  it('exception : la MÊME erreur est relevée (le runtime rend ce qu’il aurait rendu)', async () => {
    const o = opts();
    const boom = new Error('relation "x" does not exist');
    await expect(withSentinel(async () => { throw boom; }, o)(new Request('https://e/f'))).rejects.toBe(boom);
    await flush();
    expect(o.events).toHaveLength(1);
  });

  it('envoi qui lève : réponse identique', async () => {
    const original = new Response('x', { status: 500 });
    const res = await withSentinel(async () => original, opts({ write: async () => { throw new Error('panne'); } }))(new Request('https://e/f'));
    expect(res).toBe(original);
  });

  it('envoi qui ne répond jamais : la réponse n’attend pas', async () => {
    const original = new Response('x', { status: 500 });
    const t0 = Date.now();
    const res = await withSentinel(async () => original, opts({ write: () => new Promise(() => {}), timeoutMs: 5000 }))(new Request('https://e/f'));
    expect(res).toBe(original);
    expect(Date.now() - t0).toBeLessThan(200);
  });

  it('l’envoi est remis au runtime (defer), borné par le délai', async () => {
    vi.useFakeTimers();
    try {
      const deferred: Promise<unknown>[] = [];
      const o = opts({ write: () => new Promise(() => {}), defer: (p) => { deferred.push(p); }, timeoutMs: 1000 });
      await withSentinel(async () => new Response('', { status: 502 }), o)(new Request('https://e/f'));
      expect(deferred).toHaveLength(1);
      let settled = false;
      void deferred[0].then(() => { settled = true; });
      await vi.advanceTimersByTimeAsync(1001);
      expect(settled).toBe(true);
    } finally { vi.useRealTimers(); }
  });
});

describe('must : le résultat inchangé, son refus signalé', () => {
  const opts = () => { const events: SentinelEvent[] = []; return { events, o: { functionName: 'f', write: async (e: SentinelEvent) => { events.push(e); } } }; };

  it('erreur ignorée : résultat identique, refus signalé avec l’objet', async () => {
    const { events, o } = opts();
    const result = { data: null, error: { code: '42501', message: 'permission denied for table widgets' }, status: 403 };
    expect(await must(result, o, { resource: 'widgets', operation: 'insert' })).toBe(result);
    await flush();
    expect(events[0].context).toMatchObject({ resource: 'widgets', operation: 'insert', function: 'f' });
  });

  it('aucune ligne touchée : signalé seulement si on l’attendait', async () => {
    const { events, o } = opts();
    await must({ data: [], error: null }, o, { resource: 'widgets', operation: 'update' });
    await flush();
    expect(events).toHaveLength(0);
    await must({ data: [], error: null }, o, { resource: 'widgets', operation: 'update', expectRows: true });
    await must({ data: [{ id: 1 }], error: null }, o, { resource: 'widgets', operation: 'update', expectRows: true });
    await flush();
    expect(events).toHaveLength(1);
    expect(events[0].error.code).toBe(SENTINEL_NO_ROWS_CODE);
  });

  it('éteint : rien, et le résultat est rendu', async () => {
    const { events, o } = opts();
    const r = { data: null, error: { code: '42501', message: 'x' } };
    expect(await must(r, { ...o, enabled: false }, { resource: 'widgets', operation: 'insert' })).toBe(r);
    await flush();
    expect(events).toHaveLength(0);
  });
});

describe('module moniteurs : la règle de la base', () => {
  const now = new Date('2026-11-08T12:00:00Z');
  const ago = (min: number) => new Date(now.getTime() - min * 60_000);
  it('en retard au-delà de planification + tolérance, pas avant', () => {
    expect(evaluateMonitor({ expectedEveryMinutes: 60, toleranceMinutes: 60, lastSuccessAt: ago(119), lastFailureAt: null }, now)).toBe('ok');
    expect(evaluateMonitor({ expectedEveryMinutes: 60, toleranceMinutes: 60, lastSuccessAt: ago(121), lastFailureAt: null }, now)).toBe('late');
  });
  it('un échec plus récent que le dernier succès l’emporte', () => {
    expect(evaluateMonitor({ expectedEveryMinutes: 60, toleranceMinutes: 60, lastSuccessAt: ago(10), lastFailureAt: ago(5) }, now)).toBe('failed');
  });
  it('sans preuve ni planification : inconnu, jamais une alerte', () => {
    expect(evaluateMonitor({ expectedEveryMinutes: null, toleranceMinutes: null, lastSuccessAt: ago(9999), lastFailureAt: null }, now)).toBe('unknown');
    expect(evaluateMonitor({ expectedEveryMinutes: 60, toleranceMinutes: 0, lastSuccessAt: null, lastFailureAt: null }, now)).toBe('unknown');
  });
  it('tolérance par défaut, éprouvé', () => {
    expect(defaultTolerance(60)).toBe(60);
    expect(defaultTolerance(10)).toBe(110);
    expect(defaultTolerance(1440)).toBe(720);
    expect(isProven({ everRedAt: null, lastDrillDispatched: null })).toBe(false);
    expect(isProven({ everRedAt: null, lastDrillDispatched: true })).toBe(true);
  });
});
