/**
 * Sentinel — le format commun d'un événement d'erreur.
 *
 * Module PUR, sans dépendance : il tourne dans le navigateur, sous Deno
 * (edge functions) et sous Node (tests). Un hôte (SILLON est le premier) ne
 * dépend que de ce format ; rien ici ne connaît une boutique, un tenant ni
 * Supabase.
 */

/** Où l'erreur est née. Liste FERMÉE, recopiée par la contrainte SQL. */
export type SentinelSurface = 'erp' | 'portal' | 'pos' | 'site' | 'admin' | 'edge' | 'unknown';

export const SENTINEL_SURFACES: readonly SentinelSurface[] = ['erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown'];

/** Nature de l'erreur, déduite de sa forme — jamais de son seul message. */
export type SentinelErrorType =
  | 'permission_denied' // SQLSTATE 42501, RLS
  | 'database' // autre code SQLSTATE / PostgREST
  | 'edge_function' // FunctionsHttpError & co
  | 'network' // fetch refusé, hors ligne
  | 'render' // ErrorBoundary React
  | 'javascript' // Error JavaScript
  | 'unknown';

export const SENTINEL_ERROR_TYPES: readonly SentinelErrorType[] = [
  'permission_denied', 'database', 'edge_function', 'network', 'render', 'javascript', 'unknown',
];

/** Ce qu'on sait d'une erreur, quelle que soit sa forme d'origine. */
export interface NormalizedError {
  type: SentinelErrorType;
  /** Nom de la classe (TypeError, PostgrestError…), ou null. */
  name: string | null;
  /** Jamais « [object Object] » : à défaut d'un message, la forme de l'objet. */
  message: string;
  /** Code SQLSTATE, code PostgREST (PGRST…) ou code métier. */
  code: string | null;
  details: string | null;
  hint: string | null;
  stack: string | null;
}

export interface SentinelBreadcrumb {
  at: string;
  category: 'navigation' | 'query' | 'action' | 'log';
  message: string;
}

/** L'événement tel qu'il voyage du SDK au serveur. Tout y est déjà nettoyé. */
export interface SentinelEvent {
  /** Version du format. */
  v: 1;
  fingerprint: string;
  occurred_at: string;
  release: string | null;
  environment: string;
  surface: SentinelSurface;
  error: NormalizedError;
  /** Adresse de la page SANS requête ni fragment. */
  url: string | null;
  /** Boutique que l'hôte PRÉTEND : le serveur la vérifie, ne la croit jamais. */
  claimed_tenant: string | null;
  breadcrumbs: SentinelBreadcrumb[];
  /** Clés et valeurs courtes, nettoyées. */
  context: Record<string, string | number | boolean | null>;
}

/** Plafonds : un événement plus gros est tronqué par le SDK, refusé par le serveur. */
export const SENTINEL_LIMITS = {
  message: 1000,
  details: 1000,
  hint: 500,
  stack: 8000,
  url: 500,
  breadcrumbs: 20,
  breadcrumbMessage: 200,
  contextKeys: 20,
  contextValue: 200,
  /** Corps JSON entier, en octets. */
  body: 64 * 1024,
} as const;
