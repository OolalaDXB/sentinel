/**
 * Construire un événement (SDK) et le VALIDER (serveur).
 *
 * Le serveur ne croit rien du navigateur : il refuse ce qui n'a pas la forme,
 * retronque, renettoie et RECALCULE l'empreinte. Un client qui forge un corps
 * ne peut ni dépasser les plafonds, ni glisser un secret, ni choisir le
 * problème auquel son événement s'ajoute.
 */
import { fingerprintOf } from './fingerprint.ts';
import { classify, normalizeError } from './normalize.ts';
import { scrubContext, scrubText, scrubUrl } from './scrub.ts';
import {
  SENTINEL_ERROR_TYPES, SENTINEL_LIMITS, SENTINEL_SURFACES,
  type NormalizedError, type SentinelBreadcrumb, type SentinelEvent, type SentinelSurface,
} from './types.ts';

const L = SENTINEL_LIMITS;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function cleanError(e: NormalizedError): NormalizedError {
  const message = scrubText(e.message, L.message) || 'Erreur sans message';
  const code = e.code ? scrubText(e.code, 40) : null;
  const name = e.name ? scrubText(e.name, 80) : null;
  return {
    // Le type se redéduit : un client ne choisit pas sa catégorie.
    type: classify(name, message, code),
    name,
    message,
    code,
    details: e.details ? scrubText(e.details, L.details) : null,
    hint: e.hint ? scrubText(e.hint, L.hint) : null,
    stack: e.stack ? scrubText(e.stack, L.stack) : null,
  };
}

function cleanBreadcrumbs(list: unknown): SentinelBreadcrumb[] {
  if (!Array.isArray(list)) return [];
  const out: SentinelBreadcrumb[] = [];
  for (const b of list.slice(-L.breadcrumbs)) {
    if (!b || typeof b !== 'object') continue;
    const r = b as Record<string, unknown>;
    const category = ['navigation', 'query', 'action', 'log'].includes(String(r.category))
      ? (r.category as SentinelBreadcrumb['category']) : 'log';
    const at = typeof r.at === 'string' && !Number.isNaN(Date.parse(r.at)) ? new Date(r.at).toISOString() : null;
    if (!at) continue;
    const raw = String(r.message ?? '');
    // Une navigation est une adresse : jamais sa requête ni son fragment.
    const message = category === 'navigation' ? (scrubUrl(raw, L.breadcrumbMessage) ?? '') : scrubText(raw, L.breadcrumbMessage);
    out.push({ at, category, message });
  }
  return out;
}

export interface BuildInput {
  error: unknown;
  release?: string | null;
  environment?: string;
  surface?: SentinelSurface;
  url?: string | null;
  claimedTenant?: string | null;
  breadcrumbs?: SentinelBreadcrumb[];
  context?: Record<string, unknown>;
  now?: Date;
  /** Erreur de rendu React : la catégorie vient de l'appelant. */
  render?: boolean;
}

export function buildEvent(input: BuildInput): SentinelEvent {
  const normalized = cleanError(normalizeError(input.error));
  const error = input.render && normalized.type !== 'permission_denied' && normalized.type !== 'database'
    ? { ...normalized, type: 'render' as const } : normalized;
  return {
    v: 1,
    fingerprint: fingerprintOf(error),
    occurred_at: (input.now ?? new Date()).toISOString(),
    release: input.release ? scrubText(input.release, 64) : null,
    environment: scrubText(input.environment ?? 'production', 32),
    surface: SENTINEL_SURFACES.includes(input.surface as SentinelSurface) ? (input.surface as SentinelSurface) : 'unknown',
    error,
    url: scrubUrl(input.url, L.url),
    claimed_tenant: input.claimedTenant && UUID.test(input.claimedTenant) ? input.claimedTenant.toLowerCase() : null,
    breadcrumbs: cleanBreadcrumbs(input.breadcrumbs),
    context: scrubContext(input.context, L.contextKeys, L.contextValue),
  };
}

export type ValidateResult =
  | { ok: true; event: SentinelEvent }
  | { ok: false; reason: 'BODY_TOO_LARGE' | 'NOT_JSON' | 'BAD_VERSION' | 'NO_ERROR' };

/** Le contrôle du serveur. `raw` est le corps TEL QUE REÇU (texte). */
export function validateEvent(raw: string, now: Date = new Date()): ValidateResult {
  if (new TextEncoder().encode(raw).length > L.body) return { ok: false, reason: 'BODY_TOO_LARGE' };
  let body: unknown;
  try { body = JSON.parse(raw); } catch { return { ok: false, reason: 'NOT_JSON' }; }
  if (!body || typeof body !== 'object') return { ok: false, reason: 'NOT_JSON' };
  const b = body as Record<string, unknown>;
  if (b.v !== 1) return { ok: false, reason: 'BAD_VERSION' };
  const e = b.error as Record<string, unknown> | undefined;
  if (!e || typeof e !== 'object' || typeof e.message !== 'string') return { ok: false, reason: 'NO_ERROR' };

  const declaredType = SENTINEL_ERROR_TYPES.includes(e.type as never) ? (e.type as string) : null;
  const event = buildEvent({
    error: {
      name: typeof e.name === 'string' ? e.name : undefined,
      message: e.message,
      code: typeof e.code === 'string' ? e.code : undefined,
      details: typeof e.details === 'string' ? e.details : undefined,
      hint: typeof e.hint === 'string' ? e.hint : undefined,
      stack: typeof e.stack === 'string' ? e.stack : undefined,
    },
    release: typeof b.release === 'string' ? b.release : null,
    environment: typeof b.environment === 'string' ? b.environment : 'production',
    surface: b.surface as SentinelSurface,
    url: typeof b.url === 'string' ? b.url : null,
    claimedTenant: typeof b.claimed_tenant === 'string' ? b.claimed_tenant : null,
    breadcrumbs: b.breadcrumbs as SentinelBreadcrumb[],
    context: (b.context && typeof b.context === 'object' ? b.context : {}) as Record<string, unknown>,
    // L'heure du serveur fait foi : une horloge de navigateur ment.
    now,
    render: declaredType === 'render',
  });
  return { ok: true, event };
}
