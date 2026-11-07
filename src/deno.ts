/**
 * SDK Deno (edge functions) : une erreur levée par un gestionnaire devient
 * un événement `edge`, remis à un écrivain fourni par l'hôte — SILLON appelle
 * `sentinel_ingest` en service_role. La réponse reste celle que le
 * gestionnaire aurait rendue : un 500 SANS le détail, jamais une pile.
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

export function edgeEvent(error: unknown, req: Request | null, options: Omit<DenoCaptureOptions, 'write' | 'corsHeaders'>): SentinelEvent {
  return buildEvent({
    error,
    release: options.release ?? null,
    environment: options.environment ?? 'production',
    surface: 'edge',
    url: req ? new URL(req.url).pathname : null,
    context: { function: options.functionName, method: req?.method ?? null },
  });
}

export function withSentinel(
  handler: (req: Request) => Promise<Response>,
  options: DenoCaptureOptions,
): (req: Request) => Promise<Response> {
  return async (req) => {
    try {
      return await handler(req);
    } catch (error) {
      try { await options.write(edgeEvent(error, req, options)); } catch { /* jamais bloquant */ }
      return new Response(JSON.stringify({ error: 'INTERNAL_ERROR' }), {
        status: 500,
        headers: { ...(options.corsHeaders ?? {}), 'Content-Type': 'application/json' },
      });
    }
  };
}
