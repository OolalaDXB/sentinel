/**
 * Refus de données (schéma 005) : une écriture ou une lecture que la base a
 * refusée, ou une écriture qui devait toucher une ligne et n'en a touché
 * aucune. Ces échecs ne LÈVENT pas : un client de base rend `{ error }`, et un
 * appelant qui ne lit pas l'erreur ne voit rien. Ils deviennent des
 * événements ordinaires, regroupés par OBJET + OPÉRATION + CODE — jamais par
 * une valeur : deux lignes refusées de la même table sont le même problème.
 *
 * Rien ici ne lit une ligne ni un filtre : le message de la base est gardé,
 * débarrassé de ce qui est entre guillemets ou entre parenthèses après
 * « Key », où la base recopie les valeurs.
 */
import { SENTINEL_DATA_OPERATIONS, SENTINEL_NO_ROWS_CODE, type SentinelDataFailure, type SentinelDataOperation } from './types.ts';

const RESOURCE = /^[a-z_][a-z0-9_]{0,62}$/;

export interface DataFailureInput {
  resource: string;
  operation: SentinelDataOperation | string;
  /** Statut HTTP, ou null. */
  status?: number | null;
  /** SQLSTATE, code PostgREST, ou SENTINEL_NO_ROWS. */
  code?: string | null;
  /** Message de la base, s'il y en a un. */
  message?: string | null;
  hint?: string | null;
}

/** Le refus normalisé, ou null si l'objet ou l'opération n'ont pas la forme. */
export function cleanDataFailure(input: { resource?: unknown; operation?: unknown; status?: unknown } | null | undefined): SentinelDataFailure | null {
  if (!input || typeof input !== 'object') return null;
  const resource = typeof input.resource === 'string' ? input.resource.trim().toLowerCase().replace(/^public\./, '') : '';
  const operation = typeof input.operation === 'string' ? input.operation.trim().toLowerCase() : '';
  if (!RESOURCE.test(resource)) return null;
  if (!SENTINEL_DATA_OPERATIONS.includes(operation as SentinelDataOperation)) return null;
  const status = typeof input.status === 'number' && Number.isInteger(input.status) && input.status >= 100 && input.status <= 599
    ? input.status : null;
  return { resource, operation: operation as SentinelDataOperation, status };
}

/** Le message de la base sans les valeurs qu'elle recopie. */
export function redactValues(message: string): string {
  return message
    .replace(/\bKey\s*\([^)]*\)\s*=\s*\([^)]*\)/gi, 'Key (…)=(…)')
    .replace(/:\s*"[^"]*"/g, ': "…"')
    .replace(/(["'«])[^"'»]{1,200}(["'»])/g, (m, a: string, b: string) => {
      // Un nom d'objet (« relation "orders" ») reste lisible : c'est lui qui dit quoi corriger.
      const inner = m.slice(1, -1);
      return RESOURCE.test(inner) ? m : `${a}…${b}`;
    });
}

/** L'erreur à passer à `buildEvent`, et le refus qui fonde l'empreinte. */
export function dataFailureError(input: DataFailureInput): { error: Record<string, string | null>; data: SentinelDataFailure } | null {
  const data = cleanDataFailure(input);
  if (!data) return null;
  const code = input.code ? String(input.code).slice(0, 40) : (data.status ? `HTTP_${data.status}` : null);
  const base = input.message ? redactValues(String(input.message)) : null;
  const message = code === SENTINEL_NO_ROWS_CODE
    ? `${data.operation} ${data.resource} : aucune ligne touchée`
    : `${data.operation} ${data.resource} refusé (${code ?? 'sans code'})${base ? ` : ${base}` : ''}`;
  return {
    error: { name: 'DataFailure', message, code, details: null, hint: input.hint ? redactValues(String(input.hint)) : null, stack: null },
    data,
  };
}
