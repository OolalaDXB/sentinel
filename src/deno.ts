/**
 * SDK Deno : capture les exceptions, les réponses HTTP 5xx et les erreurs
 * explicites de résultats via must(). Aucun code dépendant d'un hôte.
 * Le corps des réponses n'est jamais lu pour fabriquer un événement.
 */
import { buildEvent } from './event.ts';
import type { SentinelEvent } from './types.ts';

export interface DenoCaptureOptions {
  release?: string | null;
  environment?: string;
  /** Nom de la fonction : il entre dans le contexte. */
  functionName: string;
  write: (event: SentinelEvent) => Promise<void>;
  corsHeaders?: Record<string, string>;
}

/** Contexte ajouté par l'appelant, jamais des valeurs de lignes ou de requête. */
export interface EdgeFailureContext {
  resource?: string;
  operation?: string;
}

export function edgeEvent(
  error: unknown,
  req: Request | null,
  options: Omit<DenoCaptureOptions, 'write' | 'corsHeaders'>,
  details?: EdgeFailureContext,
): SentinelEvent {
  return buildEvent({
    error,
    release: options.release ?? null,
    environment: options.environment ?? 'production',
    surface: 'edge',
    url: req ? new URL(req.url).pathname : null,
    context: {
      function: options.functionName,
      method: req?.method ?? null,
      ...(details?.resource ? { resource: details.resource } : {}),
      ...(details?.operation ? { operation: details.operation } : {}),
    },
  });
}

/**
 * Certains clients (notamment les clients de données) renvoient {error}
 * sans lever d'exception. must() enregistre le refus même si l'appelant
 * oublie de lire error, puis rend le résultat INCHANGÉ.
 *
 * Il n'interprète jamais une réponse vide comme un refus : un résultat
 * "0 ligne" doit être explicitement signalé par l'hôte après comptage.
 */
export async function must<T extends { error?: unknown }>(
  result: T | Promise<T>,
  options: DenoCaptureOptions,
  req: Request | null = null,
  details?: EdgeFailureContext,
): Promise<T> {
  const settled = await result;
  if (settled.error != null) {
    try {
      await options.write(edgeEvent(settled.error, req, options, details));
    } catch { /* l'observation ne casse jamais la fonction */ }
  }
  return settled;
}

export function withSentinel(
  handler: (req: Request) => Promise<Response>,
  options: DenoCaptureOptions,
): (req: Request) => Promise<Response> {
  return async (req) => {
    try {
      const response = await handler(req);
      if (response.status >= 500) {
        // Une réponse d'échec explicite NE LÈVE PAS : sans ce cas elle est
        // invisible. Pas de clone ni de lecture de son corps (secrets).
        try {
          await options.write(edgeEvent({
            name: 'FunctionsHttpError',
            message: `HTTP ${response.status} from ${options.functionName}`,
            code: `HTTP_${response.status}`,
          }, req, options));
        } catch { /* ne modifie jamais la réponse métier */ }
      }
      return response;
    } catch (error) {
      try { await options.write(edgeEvent(error, req, options)); } catch { /* jamais bloquant */ }
      return new Response(JSON.stringify({ error: 'INTERNAL_ERROR' }), {
        status: 500,
        headers: { ...(options.corsHeaders ?? {}), 'Content-Type': 'application/json' },
      });
    }
  };
}
