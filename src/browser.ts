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
import { buildEvent } from './event.ts';
import { isStaleChunk, normalizeError } from './normalize.ts';
import type { SentinelEvent, SentinelSurface } from './types.ts';

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
  /** Remplace l'envoi (tests). */
  transport?: (event: SentinelEvent, headers: Record<string, string>) => Promise<void> | void;
  now?: () => number;
  random?: () => number;
}

export interface Sentinel {
  captureException(error: unknown, extra?: { context?: Record<string, unknown>; render?: boolean }): SentinelEvent | null;
  addBreadcrumb(category: 'navigation' | 'query' | 'action' | 'log', message: string): void;
  /** Branche l'écoute globale ; rend la fonction qui la débranche. */
  install(target: Pick<Window, 'addEventListener' | 'removeEventListener' | 'location'>): () => void;
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

  const captureException: Sentinel['captureException'] = (error, extra) => {
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
        context: { ...(scope.context ?? {}), ...(extra?.context ?? {}) },
        now: new Date(now()),
        render: extra?.render,
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

  return {
    captureException,
    addBreadcrumb(category, message) {
      trail.add(category, message);
    },
    install(target) {
      currentUrl = target.location?.href ?? null;
      const onError = (e: Event) => {
        const ev = e as ErrorEvent;
        captureException(ev.error ?? ev.message ?? 'Erreur JavaScript');
      };
      const onRejection = (e: Event) => {
        captureException((e as PromiseRejectionEvent).reason ?? 'Promesse rejetée sans raison');
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
