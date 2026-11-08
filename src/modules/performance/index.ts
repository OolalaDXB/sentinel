/**
 * Module « performance » (schéma modules/performance/001) : collecte des Web
 * Vitals dans le navigateur, sans dépendance.
 *
 * - Échantillonné : la page est tirée au sort AU CHARGEMENT (10 % par défaut) ;
 *   non tirée, aucun observateur n'est posé.
 * - Une seule remise par chargement, quand la page passe en arrière-plan
 *   (`visibilitychange` → hidden, ou `pagehide`).
 * - Rien d'identifiant : la VERSION, la ROUTE normalisée (aucun identifiant,
 *   aucune requête), la surface, quatre nombres.
 * - Ne lève jamais : un navigateur sans `PerformanceObserver` ne mesure rien.
 */

export type VitalMetric = 'lcp' | 'inp' | 'cls' | 'ttfb';
export const VITAL_METRICS: readonly VitalMetric[] = ['lcp', 'inp', 'cls', 'ttfb'];

/** Plafonds de la réception (au-delà : une mesure aberrante, écartée). */
export const VITAL_LIMITS: Record<VitalMetric, number> = { lcp: 120_000, inp: 120_000, cls: 100, ttfb: 120_000 };

export type VitalsSample = Partial<Record<VitalMetric, number>>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Une adresse → une route : sans requête ni fragment ; un identifiant (UUID,
 * nombre, longue chaîne mêlant lettres et chiffres) devient `:id` ; `rewrite`
 * laisse l'hôte remplacer ce qu'il sait (un tenant dans l'adresse…).
 * Rend `/` pour tout ce qui ne se lit pas.
 */
export function normalizeRoute(path: string, rewrite?: (segments: string[]) => string[]): string {
  try {
    const raw = String(path ?? '').split('#')[0].split('?')[0];
    let segs = raw.split('/').filter(Boolean).map((s) => {
      let d = s;
      try { d = decodeURIComponent(s); } catch { /* segment illisible : tel quel */ }
      if (UUID.test(d) || /^\d+$/.test(d)) return ':id';
      if (d.length >= 16 && /\d/.test(d) && /[A-Za-z]/.test(d)) return ':id';
      if (!/^[A-Za-z0-9_.-]{1,60}$/.test(d)) return ':x';
      return d;
    });
    if (rewrite) segs = rewrite(segs);
    const route = `/${segs.join('/')}`.slice(0, 200);
    return /^\/[A-Za-z0-9/:_.-]{0,199}$/.test(route) ? route : '/';
  } catch {
    return '/';
  }
}

/** Les mesures valables seulement : nombres finis, positifs, sous le plafond. */
export function cleanVitals(sample: VitalsSample): VitalsSample {
  const out: VitalsSample = {};
  for (const m of VITAL_METRICS) {
    const v = sample[m];
    if (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= VITAL_LIMITS[m]) out[m] = m === 'cls' ? Math.round(v * 10000) / 10000 : Math.round(v);
  }
  return out;
}

export interface VitalsBeacon {
  type: 'vitals';
  release: string | null;
  route: string;
  surface: string;
  metrics: VitalsSample;
}

type ObserverCtor = new (cb: (list: { getEntries(): Array<Record<string, unknown>> }) => void) => {
  observe(opts: Record<string, unknown>): void;
  disconnect(): void;
};

export interface WebVitalsOptions {
  release: string | null;
  route: () => string;
  surface: () => string;
  send: (beacon: VitalsBeacon) => unknown;
  /** 0 à 1 ; 0,1 par défaut. */
  sampleRate?: number;
  random?: () => number;
  /** Fenêtre du navigateur (tests : un faux). */
  target?: {
    addEventListener(type: string, cb: () => void, opts?: unknown): void;
    document?: { visibilityState?: string; addEventListener?(type: string, cb: () => void): void };
    PerformanceObserver?: ObserverCtor;
    performance?: { getEntriesByType?(type: string): Array<Record<string, unknown>> };
  };
}

/** Rend vrai si la page est mesurée. */
export function collectWebVitals(options: WebVitalsOptions): boolean {
  try {
    const random = options.random ?? Math.random;
    if (random() >= (options.sampleRate ?? 0.1)) return false;
    const target = options.target ?? (globalThis as unknown as WebVitalsOptions['target']);
    const PO = target?.PerformanceObserver;
    if (!target || !PO) return false;
    const route = options.route();
    const surface = options.surface();
    const sample: VitalsSample = {};
    let cls = 0;
    let sent = false;
    const watch = (type: string, onEntry: (e: Record<string, unknown>) => void, extra: Record<string, unknown> = {}) => {
      try {
        new PO((list) => { for (const e of list.getEntries()) onEntry(e); }).observe({ type, buffered: true, ...extra });
      } catch { /* type inconnu de ce navigateur */ }
    };
    watch('largest-contentful-paint', (e) => { sample.lcp = Number(e.startTime ?? 0); });
    watch('layout-shift', (e) => { if (!e.hadRecentInput) { cls += Number(e.value ?? 0); sample.cls = cls; } });
    watch('event', (e) => { const d = Number(e.duration ?? 0); if (d > (sample.inp ?? 0)) sample.inp = d; }, { durationThreshold: 40 });
    watch('first-input', (e) => { const d = Number(e.duration ?? 0); if (d > (sample.inp ?? 0)) sample.inp = d; });
    try {
      const nav = target.performance?.getEntriesByType?.('navigation')?.[0];
      if (nav && typeof nav.responseStart === 'number' && nav.responseStart > 0) sample.ttfb = nav.responseStart;
    } catch { /* pas de mesure de navigation */ }
    const flush = () => {
      if (sent) return;
      try {
        const metrics = cleanVitals(sample);
        if (Object.keys(metrics).length === 0) return;
        sent = true;
        void Promise.resolve().then(() => options.send({ type: 'vitals', release: options.release, route, surface, metrics })).catch(() => undefined);
      } catch { /* jamais bloquant */ }
    };
    target.document?.addEventListener?.('visibilitychange', () => { if (target.document?.visibilityState === 'hidden') flush(); });
    target.addEventListener('pagehide', flush, { capture: true });
    return true;
  } catch {
    return false;
  }
}
