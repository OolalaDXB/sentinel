/**
 * Lot 4 : Web Vitals (collecte, route normalisée, mesures nettoyées) et
 * règle de disponibilité HTTP. Paquet seul.
 */
import { describe, expect, it } from 'vitest';
import { cleanVitals, collectWebVitals, normalizeRoute, type VitalsBeacon } from '../src/modules/performance/index.ts';
import { availability, consecutiveFailures, isHealthyStatus } from '../src/modules/uptime/index.ts';

const flush = () => new Promise((r) => setTimeout(r, 0));

/** Un faux navigateur : observateurs par type, événements de page. */
function fakeWindow(opts: { observer?: boolean; badTypes?: string[] } = {}) {
  const observers: Record<string, (list: { getEntries(): Array<Record<string, unknown>> }) => void> = {};
  const page: Record<string, () => void> = {};
  const doc: Record<string, () => void> = {};
  class PO {
    cb: (list: { getEntries(): Array<Record<string, unknown>> }) => void;
    constructor(cb: PO['cb']) { this.cb = cb; }
    observe(o: { type: string }) { if (opts.badTypes?.includes(o.type)) throw new Error('type inconnu'); observers[o.type] = this.cb; }
    disconnect() {}
  }
  const document = { visibilityState: 'visible', addEventListener: (t: string, cb: () => void) => { doc[t] = cb; } };
  const target = {
    addEventListener: (t: string, cb: () => void) => { page[t] = cb; },
    document,
    PerformanceObserver: opts.observer === false ? undefined : PO,
    performance: { getEntriesByType: (t: string) => (t === 'navigation' ? [{ responseStart: 180.4 }] : []) },
  };
  const emit = (type: string, ...entries: Array<Record<string, unknown>>) => observers[type]?.({ getEntries: () => entries });
  const hide = () => { document.visibilityState = 'hidden'; doc.visibilitychange?.(); };
  return { target, emit, hide, pagehide: () => page.pagehide?.(), observers };
}

describe('route normalisée : aucun identifiant n’entre dans une mesure', () => {
  it('UUID, nombre, longue chaîne aléatoire → :id ; requête et fragment retirés', () => {
    expect(normalizeRoute('/t/acme/widgets/0f0e0d0c-0b0a-4908-8706-050403020100?tab=a#x')).toBe('/t/acme/widgets/:id');
    expect(normalizeRoute('/reports/12345/pdf')).toBe('/reports/:id/pdf');
    expect(normalizeRoute('/pay/abcd1234efgh5678ijkl')).toBe('/pay/:id');
    expect(normalizeRoute('/a b/c')).toBe('/:x/c');
    // Un UUID tout en chiffres échappe à la règle des longues chaînes mêlées.
    expect(normalizeRoute('/r/12345678-1234-4123-8123-123456789012')).toBe('/r/:id');
    // Une requête sur un segment court : elle ne déforme pas la route.
    expect(normalizeRoute('/catalog?tab=a')).toBe('/catalog');
    expect(normalizeRoute('')).toBe('/');
  });
  it('l’hôte réécrit ce qu’il sait', () => {
    expect(normalizeRoute('/t/acme/widgets', (s) => (s[0] === 't' ? ['t', ':tenant', ...s.slice(2)] : s))).toBe('/t/:tenant/widgets');
    expect(normalizeRoute('/x', () => { throw new Error('panne'); })).toBe('/');
  });
});

describe('mesures nettoyées', () => {
  it('nombres finis, positifs, sous le plafond ; arrondis', () => {
    expect(cleanVitals({ lcp: 1234.6, inp: -1, cls: 0.12345, ttfb: Number.NaN })).toEqual({ lcp: 1235, cls: 0.1235 });
    expect(cleanVitals({ lcp: 500000, cls: 101 })).toEqual({});
  });
});

describe('collecte des Web Vitals', () => {
  const base = (w: ReturnType<typeof fakeWindow>, sent: VitalsBeacon[], random = () => 0.05) => ({
    release: 'v1', route: () => '/t/:tenant/widgets', surface: () => 'erp',
    send: (b: VitalsBeacon) => { sent.push(b); }, random, target: w.target as never,
  });

  it('page non tirée au sort (90 %) : aucun observateur, rien ne part', async () => {
    const w = fakeWindow(); const sent: VitalsBeacon[] = [];
    expect(collectWebVitals(base(w, sent, () => 0.5))).toBe(false);
    expect(Object.keys(w.observers)).toHaveLength(0);
    w.hide(); await flush();
    expect(sent).toHaveLength(0);
  });

  it('page tirée : LCP le dernier, CLS sans les décalages voulus, INP le pire, TTFB ; une remise', async () => {
    const w = fakeWindow(); const sent: VitalsBeacon[] = [];
    expect(collectWebVitals(base(w, sent))).toBe(true);
    w.emit('largest-contentful-paint', { startTime: 900 }, { startTime: 1800 });
    w.emit('layout-shift', { value: 0.1, hadRecentInput: false }, { value: 0.5, hadRecentInput: true }, { value: 0.05, hadRecentInput: false });
    w.emit('event', { duration: 80 }, { duration: 240 }, { duration: 120 });
    w.hide(); w.pagehide(); w.hide();
    await flush();
    expect(sent).toHaveLength(1);
    expect(sent[0]).toEqual({ type: 'vitals', release: 'v1', route: '/t/:tenant/widgets', surface: 'erp', metrics: { lcp: 1800, cls: 0.15, inp: 240, ttfb: 180 } });
  });

  it('rien d’identifiant ne part : type, version, route, surface, mesures', async () => {
    const w = fakeWindow(); const sent: VitalsBeacon[] = [];
    collectWebVitals(base(w, sent));
    w.emit('largest-contentful-paint', { startTime: 500, url: 'https://x/img.png?token=abc', element: {} });
    w.pagehide(); await flush();
    expect(Object.keys(sent[0]).sort()).toEqual(['metrics', 'release', 'route', 'surface', 'type']);
    expect(Object.keys(sent[0].metrics).sort()).toEqual(['lcp', 'ttfb']);
  });

  it('navigateur sans observateur, type inconnu, envoi qui rejette : rien ne lève, rien en l’air', async () => {
    const rejected: unknown[] = [];
    const on = (e: unknown) => { rejected.push(e); };
    process.on('unhandledRejection', on);
    try {
      expect(collectWebVitals(base(fakeWindow({ observer: false }), []))).toBe(false);
      const w = fakeWindow({ badTypes: ['event', 'layout-shift'] }); const sent: VitalsBeacon[] = [];
      expect(collectWebVitals({ ...base(w, sent), send: () => Promise.reject(new Error('panne')) })).toBe(true);
      w.emit('largest-contentful-paint', { startTime: 700 });
      expect(() => w.pagehide()).not.toThrow();
      for (let i = 0; i < 4; i++) await flush();
    } finally { process.off('unhandledRejection', on); }
    expect(rejected).toEqual([]);
  });

  it('sans aucune mesure, rien ne part', async () => {
    const w = fakeWindow(); const sent: VitalsBeacon[] = [];
    collectWebVitals({ ...base(w, sent), target: { ...w.target, performance: { getEntriesByType: () => [] } } as never });
    w.pagehide(); await flush();
    expect(sent).toHaveLength(0);
  });
});

describe('disponibilité : la règle de la base', () => {
  it('statut attendu, sinon 2xx/3xx ; délai dépassé jamais sain', () => {
    expect(isHealthyStatus(200, null)).toBe(true);
    expect(isHealthyStatus(301, null)).toBe(true);
    expect(isHealthyStatus(404, null)).toBe(false);
    expect(isHealthyStatus(401, [401])).toBe(true);
    expect(isHealthyStatus(200, [401])).toBe(false);
    expect(isHealthyStatus(200, null, true)).toBe(false);
    expect(isHealthyStatus(0, null)).toBe(false);
    expect(isHealthyStatus(null, null)).toBe(false);
  });
  it('échecs d’affilée depuis le dernier succès, une attente ne compte pas', () => {
    expect(consecutiveFailures([{ healthy: null }, { healthy: false }, { healthy: false }, { healthy: true }, { healthy: false }])).toBe(2);
    expect(consecutiveFailures([{ healthy: true }, { healthy: false }])).toBe(0);
    expect(consecutiveFailures([])).toBe(0);
  });
  it('disponibilité : jamais 100 % sans vérification', () => {
    expect(availability(0, 0)).toBeNull();
    expect(availability(9, 10)).toBe(0.9);
  });
});
