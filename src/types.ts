/**
 * Sentinel — le format commun d'un événement d'erreur.
 *
 * Module PUR, sans dépendance : il tourne dans le navigateur, sous Deno
 * (edge functions) et sous Node (tests). Un hôte ne dépend que de ce
 * format ; rien ici ne connaît le métier de l'hôte ni son fournisseur de base.
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
  /** Tenant que l'hôte PRÉTEND : le serveur le vérifie, ne le croit jamais. */
  claimed_tenant: string | null;
  breadcrumbs: SentinelBreadcrumb[];
  /** Clés et valeurs courtes, nettoyées. */
  context: Record<string, string | number | boolean | null>;
  /**
   * Refus d'une écriture ou d'une lecture de données (schéma 005) : l'objet,
   * l'opération, le statut HTTP. Facultatif : un événement sans lui reste un
   * événement v1. Quand il est là, l'empreinte se fonde sur lui.
   */
  data?: SentinelDataFailure;
}

/** Opérations sur des données. Liste FERMÉE. */
export type SentinelDataOperation = 'select' | 'insert' | 'update' | 'upsert' | 'delete' | 'rpc';

export const SENTINEL_DATA_OPERATIONS: readonly SentinelDataOperation[] = ['select', 'insert', 'update', 'upsert', 'delete', 'rpc'];

/**
 * Un refus de données : QUOI (objet), COMMENT (opération), le statut et le
 * code. Jamais une valeur de ligne ni un filtre de requête.
 */
export interface SentinelDataFailure {
  /** Nom d'une table, d'une vue ou d'une fonction : `[a-z_][a-z0-9_]*`, 63 au plus. */
  resource: string;
  operation: SentinelDataOperation;
  /** Statut HTTP de la réponse, ou null hors HTTP. */
  status: number | null;
}

/** Code d'une écriture « qui devait toucher une ligne » et n'en a touché aucune. */
export const SENTINEL_NO_ROWS_CODE = 'SENTINEL_NO_ROWS';

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
