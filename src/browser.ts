/**
 * SDK navigateur : écoute globale (erreurs, promesses rejetées), capture
 * manuelle, fil d'actions, et envoi PRUDENT.
 *
 * - Ne lève jamais : une panne de Sentinel ne casse pas l'application.
 * - Ne répète pas : la même empreinte n'est envoyée qu'une fois par minute.
 * - Ne noie pas le serveur : 10 événements par minute au plus, par onglet.
 * - Les fragments périmés après une mise en ligne sont du BRUIT, pas un
 *   incident : l'hôte recharge déjà la page.
 */
import { BreadcrumbTrail } from './breadcrumbs.ts';
import { dataFailureError, type DataFailureInput } from './data.ts';
import { buildEvent } from './event.ts';
import { isStaleChunk, normalizeError } from './normalize.ts';
import type { SentinelDataFailure, SentinelEvent, SentinelSurface } from './types.ts';

export interface SentinelOptions {
  endpoint: string;
  release?: string | null;
  environment?: string;
  /** Lu à chaque capture : surface, boutique prétendue, contexte. */
  scope?: () => { surface?: SentinelSurface; claimedTenant?: string | null; context?: Record<string, unknown> };
  /** En-têtes ajoutés à l'envoi (jeton de session, clé publique). Peut être asynchrone. */
  headers?: () => Record<string, string> | Promise<Record<string, string>>;
  /** 0 à 1 ; 1 par défaut. */
  sampleRate?: number;
  maxPerMinute?: number;
  dedupeMs?: number;
  /** Erreurs à ignorer, par message. */
  ignore?: RegExp[];
  /**
   * Appelé (sans jamais lever) quand une erreur NON attrapée remonte à
   * l'écoute globale : l'hôte y marque la session « plantée ».
   */
  onUnhandled?: () => void;
  /** Remplace l'envoi (tests). */
  transport?: (event: SentinelEvent, headers: Record<string, string>) => Promise<void> | void;
  now?: () => number;
  random?: () => number;
}

export interface Sentinel {
  captureException(error: unknown, extra?: { context?: Record<string, unknown>; render?: boolean }): SentinelEvent | null;
  /**
   * Un refus de données que personne ne lit (schéma 005). Même dédoublonnage
   * et même débit qu'une exception ; ne lève jamais.
   */
  captureDataFailure(input: DataFailureInput): SentinelEvent | null;
  addBreadcrumb(category: 'navigation' | 'query' | 'action' | 'log', message: string): void;
  /** Branche l'écoute globale ; rend la fonction qui la débranche. */
  install(target: Pick<Window, 'addEventListener' | 'removeEventListener' | 'location'>): () => void;
}

/** Identifiant v4 ; `crypto.randomUUID` quand il existe, sinon tiré au hasard. */
export function randomId(random: () => number = Math.random): string {
  try {
    const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
    if (c?.randomUUID) return c.randomUUID();
  } catch { /* repli ci-dessous */ }
  const h = Array.from({ length: 32 }, () => Math.floor(random() * 16).toString(16));
  h[12] = '4';
  h[16] = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  const s = h.join('');
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
}

export function createSentinel(options: SentinelOptions): Sentinel {
  const now = options.now ?? (() => Date.now());
  const random = options.random ?? Math.random;
  const maxPerMinute = options.maxPerMinute ?? 10;
  const dedupeMs = options.dedupeMs ?? 60_000;
  const trail = new BreadcrumbTrail(20, () => new Date(now()));
  const lastSent = new Map<string, number>();
  let windowStart = 0;
  let windowCount = 0;
  let currentUrl: string | null = null;

  const send = async (event: SentinelEvent) => {
    try {
      const headers = { 'Content-Type': 'application/json', ...((await options.headers?.()) ?? {}) };
      if (options.transport) { await options.transport(event, headers); return; }
      await fetch(options.endpoint, { method: 'POST', headers, body: JSON.stringify(event), keepalive: true });
    } catch {
      // Une erreur d'envoi ne se capture pas : elle bouclerait.
    }
  };

  const capture = (error: unknown, extra?: { context?: Record<string, unknown>; render?: boolean; data?: SentinelDataFailure }) => {
    try {
      const n = normalizeError(error);
      if (isStaleChunk(n.message)) return null;
      if ((options.ignore ?? []).some((rx) => rx.test(n.message))) return null;
      if (random() >= (options.sampleRate ?? 1)) return null;
      const scope = options.scope?.() ?? {};
      const event = buildEvent({
        error,
        release: options.release,
        environment: options.environment,
        surface: scope.surface,
        url: currentUrl,
        claimedTenant: scope.claimedTenant,
        breadcrumbs: trail.list(),
        // Un identifiant tiré ICI, sans lien avec la personne : il permet de
        // rattacher un retour utilisateur à CET événement (schéma 006).
        context: { ...(scope.context ?? {}), ...(extra?.context ?? {}), client_event_id: randomId(random) },
        now: new Date(now()),
        render: extra?.render,
        data: extra?.data,
      });
      const t = now();
      const prev = lastSent.get(event.fingerprint);
      if (prev !== undefined && t - prev < dedupeMs) return null;
      if (t - windowStart >= 60_000) { windowStart = t; windowCount = 0; }
      if (windowCount >= maxPerMinute) return null;
      windowCount += 1;
      lastSent.set(event.fingerprint, t);
      void send(event);
      return event;
    } catch {
      return null;
    }
  };

  const captureException: Sentinel['captureException'] = (error, extra) => capture(error, extra);

  const captureDataFailure: Sentinel['captureDataFailure'] = (input) => {
    try {
      const built = dataFailureError(input);
      return built ? capture(built.error, { data: built.data }) : null;
    } catch {
      return null;
    }
  };

  return {
    captureException,
    captureDataFailure,
    addBreadcrumb(category, message) {
      trail.add(category, message);
    },
    install(target) {
      currentUrl = target.location?.href ?? null;
      const unhandled = () => { try { options.onUnhandled?.(); } catch { /* jamais bloquant */ } };
      const onError = (e: Event) => {
        const ev = e as ErrorEvent;
        captureException(ev.error ?? ev.message ?? 'Erreur JavaScript');
        unhandled();
      };
      const onRejection = (e: Event) => {
        captureException((e as PromiseRejectionEvent).reason ?? 'Promesse rejetée sans raison');
        unhandled();
      };
      const onNavigate = () => {
        currentUrl = target.location?.href ?? null;
        trail.add('navigation', currentUrl ?? '');
      };
      target.addEventListener('error', onError);
      target.addEventListener('unhandledrejection', onRejection);
      target.addEventListener('popstate', onNavigate);
      target.addEventListener('sentinel:navigate', onNavigate);
      return () => {
        target.removeEventListener('error', onError);
        target.removeEventListener('unhandledrejection', onRejection);
        target.removeEventListener('popstate', onNavigate);
        target.removeEventListener('sentinel:navigate', onNavigate);
      };
    },
  };
}
