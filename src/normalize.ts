/**
 * Une erreur, quelle que soit sa forme, devient un `NormalizedError`.
 *
 * Origine : 9 erreurs du journal SILLON portaient le message
 * « [object Object] ». Une erreur Supabase (PostgrestError) est un OBJET, pas
 * une `Error` : `String(err)` le rendait illisible et perdait son code,
 * son détail et son indice — exactement ce qui dit quoi faire.
 */
import type { NormalizedError, SentinelErrorType } from './types.ts';

const STALE_CHUNK = /Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module/i;
const NETWORK = /Failed to fetch|NetworkError|Load failed|network request failed|ERR_INTERNET_DISCONNECTED/i;

type Loose = Record<string, unknown>;

const str = (v: unknown): string | null => {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string') return v.trim() === '' ? null : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return null;
};

/** La forme d'un objet sans message : ses clés et leur type, jamais ses valeurs. */
function shapeOf(o: Loose): string {
  const keys = Object.keys(o).slice(0, 8);
  if (keys.length === 0) return 'Objet vide levé comme erreur';
  return `Objet levé comme erreur {${keys.map((k) => `${k}: ${typeof o[k]}`).join(', ')}}`;
}

export function classify(name: string | null, message: string, code: string | null): SentinelErrorType {
  if (code === '42501' || /row-level security|permission denied/i.test(message)) return 'permission_denied';
  if (code && (/^[0-9A-Z]{5}$/.test(code) || /^PGRST/.test(code))) return 'database';
  if (name && /^Functions(Http|Relay|Fetch)Error$/.test(name)) return 'edge_function';
  if (NETWORK.test(message)) return 'network';
  if (name && /Error$/.test(name)) return 'javascript';
  return 'unknown';
}

export function isStaleChunk(message: string): boolean {
  return STALE_CHUNK.test(message);
}

export function normalizeError(input: unknown): NormalizedError {
  if (input === null || input === undefined) {
    return { type: 'unknown', name: null, message: 'Erreur sans valeur (null)', code: null, details: null, hint: null, stack: null };
  }
  if (typeof input === 'string' || typeof input === 'number' || typeof input === 'boolean') {
    const message = String(input).trim() || 'Erreur vide';
    return { type: classify(null, message, null), name: null, message, code: null, details: null, hint: null, stack: null };
  }

  const o = input as Loose;
  const name = str(o.name) ?? (input instanceof Error ? input.constructor?.name ?? 'Error' : null);
  let message = str(o.message) ?? str(o.error_description) ?? str(o.error) ?? str(o.msg);
  // Une erreur d'edge function porte le corps de la réponse dans `context`.
  const context = (o.context ?? null) as Loose | null;
  const code = str(o.code) ?? str(o.error_code) ?? str(context && (context as Loose).code) ?? null;
  const details = str(o.details);
  const hint = str(o.hint);
  if (!message) {
    // Erreur imbriquée (`{ error: { message } }`, `cause`).
    const nested = (o.error && typeof o.error === 'object' ? o.error : o.cause) as Loose | undefined;
    message = nested && typeof nested === 'object' ? str(nested.message) : null;
  }
  if (!message) message = shapeOf(o);
  const stack = str(o.stack);
  return { type: classify(name, message, code), name, message, code, details, hint, stack };
}
