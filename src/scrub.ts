/**
 * Ce qui ne sort jamais du navigateur, et que le serveur retire une seconde
 * fois : adresses e-mail, jetons (JWT, Bearer, clés Supabase, longues chaînes
 * aléatoires), requête et fragment d'une adresse — un lien magique porte son
 * jeton d'accès dans le fragment (incident SILLON du 2026-11-07).
 */

const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const PROVIDER_KEY = /\b(sb_secret|sb_publishable|sk_live|sk_test|rk_live|rk_test|pk_live|pk_test)_[A-Za-z0-9]{8,}\b/g;
/** Paramètre d'adresse dont la valeur est un secret, où qu'il apparaisse. */
const SECRET_PARAM = /([?&#](?:access_token|refresh_token|token|code|apikey|api_key|key|password|secret)=)[^&#\s"']+/gi;
/** Longue chaîne sans espace mêlant lettres et chiffres : un jeton probable. */
const LONG_TOKEN = /\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{40,}\b/g;

export function scrubText(input: string | null | undefined, max = Infinity): string {
  if (input === null || input === undefined) return '';
  const out = String(input)
    .replace(JWT, '[jwt]')
    .replace(BEARER, '$1 [secret]')
    .replace(PROVIDER_KEY, '$1_[secret]')
    .replace(SECRET_PARAM, '$1[secret]')
    .replace(EMAIL, '[email]')
    .replace(LONG_TOKEN, '[token]');
  return out.length > max ? `${out.slice(0, max - 1)}…` : out;
}

/** Une adresse sans requête ni fragment ; « null » si ce n'en est pas une. */
export function scrubUrl(input: string | null | undefined, max = 500): string | null {
  if (!input) return null;
  const raw = String(input).split('#')[0].split('?')[0];
  const cleaned = scrubText(raw, max);
  return cleaned || null;
}

/** Contexte : clés courtes, valeurs scalaires nettoyées, nombre de clés plafonné. */
export function scrubContext(
  input: Record<string, unknown> | null | undefined,
  maxKeys: number,
  maxValue: number,
): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  if (!input || typeof input !== 'object') return out;
  for (const [k, v] of Object.entries(input).slice(0, maxKeys)) {
    const key = k.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 40);
    if (!key) continue;
    if (v === null || v === undefined) out[key] = null;
    else if (typeof v === 'number') out[key] = Number.isFinite(v) ? v : null;
    else if (typeof v === 'boolean') out[key] = v;
    else out[key] = scrubText(typeof v === 'string' ? v : JSON.stringify(v), maxValue);
  }
  return out;
}
