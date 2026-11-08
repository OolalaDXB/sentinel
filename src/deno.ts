/**
 * SDK Deno (edge functions), schéma 005.
 *
 * `withSentinel(handler)` observe un gestionnaire SANS le changer :
 *   - une exception est inscrite puis RELEVÉE telle quelle — le runtime rend
 *     ce qu'il aurait rendu sans l'enrobage ;
 *   - une réponse ≥ 500 est inscrite et rendue telle quelle (même objet : ni
 *     statut, ni en-tête, ni corps ne bougent ; le corps n'est jamais lu) ;
 *   - éteint (`enabled` faux), il rend le gestionnaire lui-même.
 * `must(résultat)` inscrit l'erreur d'un résultat `{ error }` qu'un appelant
 * ignorerait, et, sur demande, une écriture qui n'a touché aucune ligne ; il
 * rend le résultat INCHANGÉ.
 *
 * L'envoi n'est jamais attendu : il part en arrière-plan (`defer`, que l'hôte
 * relie à son runtime pour qu'il survive à la réponse), borné par
 * `timeoutMs`, et une panne d'envoi n'est jamais visible.
 */
import { dataFailureError, type DataFailureInput } from './data.ts';
import { buildEvent } from './event.ts';
import { SENTINEL_NO_ROWS_CODE, type SentinelDataFailure, type SentinelEvent } from './types.ts';

export interface DenoCaptureOptions {
  release?: string | null;
  environment?: string;
  /** Nom de la fonction : il entre dans le contexte. */
  functionName: string;
  write: (event: SentinelEvent) => Promise<void>;
  /** Interrupteur : faux ⇒ aucune observation. Vrai par défaut. */
  enabled?: boolean | (() => boolean);
  /** Garde vivante une promesse au-delà de la réponse (ex. `waitUntil` du runtime). */
  defer?: (promise: Promise<unknown>) => void;
  /** Délai maximal d'un envoi, en millisecondes (2 000 par défaut). */
  timeoutMs?: number;
}

const isEnabled = (o: Pick<DenoCaptureOptions, 'enabled'>): boolean => {
  try {
    return typeof o.enabled === 'function' ? o.enabled() === true : o.enabled !== false;
  } catch {
    return false;
  }
};

/** Envoi en arrière-plan, borné, muet : la seule porte de sortie du SDK Deno. */
export function dispatchInBackground(options: DenoCaptureOptions, make: () => SentinelEvent | null): void {
  try {
    const event = make();
    if (!event) return;
    const timeout = Math.max(1, options.timeoutMs ?? 2000);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const bounded = Promise.race([
      Promise.resolve().then(() => options.write(event)),
      new Promise<void>((resolve) => { timer = setTimeout(resolve, timeout); }),
    ]).catch(() => undefined).finally(() => { if (timer !== undefined) clearTimeout(timer); });
    try { options.defer?.(bounded); } catch { /* jamais bloquant */ }
  } catch {
    // Construire l'événement a échoué : rien ne sort, rien ne casse.
  }
}

export function edgeEvent(
  error: unknown,
  req: Request | null,
  options: Pick<DenoCaptureOptions, 'release' | 'environment' | 'functionName'>,
  extra?: { data?: SentinelDataFailure | null },
): SentinelEvent {
  let path: string | null = null;
  try { path = req ? new URL(req.url).pathname : null; } catch { path = null; }
  return buildEvent({
    error,
    release: options.release ?? null,
    environment: options.environment ?? 'production',
    surface: 'edge',
    url: path,
    context: { function: options.functionName, method: req?.method ?? null },
    data: extra?.data ?? null,
  });
}

export function withSentinel(
  handler: (req: Request) => Promise<Response>,
  options: DenoCaptureOptions,
): (req: Request) => Promise<Response> {
  if (!isEnabled(options)) return handler;
  return async (req) => {
    let response: Response;
    try {
      response = await handler(req);
    } catch (error) {
      dispatchInBackground(options, () => edgeEvent(error, req, options));
      throw error;
    }
    try {
      if (response && typeof response.status === 'number' && response.status >= 500) {
        const status = response.status;
        dispatchInBackground(options, () => edgeEvent(
          { name: 'FunctionsHttpError', message: `HTTP ${status} rendu par ${options.functionName}`, code: `HTTP_${status}` },
          req, options));
      }
    } catch { /* jamais bloquant */ }
    return response;
  };
}

export interface MustOptions extends Omit<DataFailureInput, 'code' | 'message' | 'hint' | 'status'> {
  /** Une écriture qui devait toucher au moins une ligne. */
  expectRows?: boolean;
}

/**
 * Le résultat d'un client de base, rendu INCHANGÉ ; son erreur, ou l'absence
 * de ligne attendue, part en arrière-plan.
 */
export async function must<T extends { error?: unknown; data?: unknown; count?: number | null; status?: number }>(
  result: T | PromiseLike<T>,
  options: DenoCaptureOptions,
  what: MustOptions,
  req: Request | null = null,
): Promise<T> {
  const settled = await result;
  if (!isEnabled(options)) return settled;
  try {
    const err = settled?.error as { code?: unknown; message?: unknown; hint?: unknown } | null | undefined;
    let input: DataFailureInput | null = null;
    if (err != null) {
      input = {
        ...what,
        status: typeof settled.status === 'number' ? settled.status : null,
        code: typeof err.code === 'string' ? err.code : null,
        message: typeof err.message === 'string' ? err.message : null,
        hint: typeof err.hint === 'string' ? err.hint : null,
      };
    } else if (what.expectRows) {
      const rows = Array.isArray(settled?.data) ? settled.data.length : (settled?.data != null ? 1 : 0);
      const touched = typeof settled?.count === 'number' ? Math.max(settled.count, rows) : rows;
      if (touched === 0) input = { ...what, status: typeof settled.status === 'number' ? settled.status : null, code: SENTINEL_NO_ROWS_CODE };
    }
    if (input) {
      const built = dataFailureError(input);
      if (built) dispatchInBackground(options, () => edgeEvent(built.error, req, options, { data: built.data }));
    }
  } catch { /* jamais bloquant */ }
  return settled;
}
