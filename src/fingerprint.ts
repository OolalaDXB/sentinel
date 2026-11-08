/**
 * L'empreinte regroupe les occurrences d'un même défaut en UN problème.
 *
 * Type + premières lignes de pile du code de l'application (fonction, sans
 * ligne ni colonne ni nom de fichier haché par le bundler) ; à défaut de
 * pile utilisable — et une pile MINIFIÉE ne l'est pas (lot 4b : « mu »,
 * « Ex », « xjt » changent à chaque déploiement, une même erreur serait un
 * problème nouveau à chaque version) —, le message normalisé — minuscules, chiffres en « # »,
 * identifiants en « <id> », texte entre guillemets en « '…' ». « took 37261ms »
 * et « took 12840ms » sont le même problème ; deux appelants différents d'une
 * même erreur générique ne le sont pas.
 */
import type { NormalizedError, SentinelDataFailure } from './types.ts';

export function normalizeMessage(message: string): string {
  return message
    .toLowerCase()
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '<id>')
    .replace(/(["'«])[^"'»]{1,80}(["'»])/g, "'…'")
    .replace(/[0-9]+/g, '#')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

/**
 * Un nom de 1 à 3 caractères est celui qu'a donné le minifieur, pas l'auteur :
 * il change d'un déploiement à l'autre et ne peut pas fonder une empreinte.
 * La partie après le dernier point compte (« Object.mu », « t.Ex »).
 */
export function isMinifiedName(fn: string): boolean {
  const last = fn.split('.').pop() ?? fn;
  return /^[A-Za-z_$][\w$]{0,2}$/.test(last);
}

/** Les fonctions de la pile, du plus profond au plus haut, hors dépendances. */
export function stackFunctions(stack: string | null | undefined, max = 3): string[] {
  if (!stack) return [];
  const out: string[] = [];
  for (const line of stack.split('\n')) {
    if (/node_modules|\/deps\/|chunk-[A-Z0-9]+|react-dom|scheduler|esm\.sh/i.test(line)) continue;
    // V8 : « at fn (url:1:2) » ; Firefox/Safari : « fn@url:1:2 ».
    const m = /^\s*at\s+([^\s(]+)\s*\(/.exec(line) ?? /^\s*([^@\s]+)@/.exec(line);
    if (!m) continue;
    const fn = m[1].replace(/^(async|new)\s+/, '').replace(/\$[0-9]+$/, '');
    if (!fn || fn === '<anonymous>' || /^Object\.|^Array\./.test(fn) || isMinifiedName(fn)) continue;
    out.push(fn);
    if (out.length >= max) break;
  }
  return out;
}

/** FNV-1a 32 bits, en hexadécimal : identique dans le navigateur, sous Deno et sous Node. */
export function hash32(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/**
 * Un refus de données (schéma 005) se regroupe par OBJET + OPÉRATION + CODE,
 * jamais par le message ni par la pile : deux refus de la même table, quelle
 * que soit la ligne ou l'écran, sont le même problème.
 */
export function fingerprintOf(error: NormalizedError, data?: SentinelDataFailure | null): string {
  if (data) return `${error.type}:${hash32(`data|${data.resource}|${data.operation}|${error.code ?? ''}`)}`;
  const frames = stackFunctions(error.stack);
  const basis = frames.length > 0
    ? `${error.type}|${error.code ?? ''}|${frames.join('>')}`
    : `${error.type}|${error.code ?? ''}|${normalizeMessage(error.message)}`;
  return `${error.type}:${hash32(basis)}`;
}
