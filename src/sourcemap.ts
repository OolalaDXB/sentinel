/**
 * Lire une pile minifiée avec la source map de SA version (lot 4b).
 *
 * Le navigateur envoie « at mu (…/assets/index-DRIdWA7f.js:863:64817) » :
 * illisible, et différent à chaque déploiement. Les source maps de chaque
 * version sont gardées à part (jamais servies au public) ; ce module, PUR,
 * retrouve le fichier, la ligne et le nom d'origine. Il ne lit que le champ
 * `mappings` (VLQ base 64) et ne garde que la ligne demandée.
 */

export interface StackFrame {
  fn: string | null;
  url: string;
  /** Nom du fichier de la version (« index-DRIdWA7f.js »), sans chemin ni requête. */
  file: string;
  line: number;
  column: number;
}

export interface RawSourceMap {
  version: number;
  sources: string[];
  names?: string[];
  mappings: string;
  sourceRoot?: string;
}

export interface OriginalPosition {
  source: string;
  line: number;
  column: number;
  name: string | null;
}

export interface SymbolicatedFrame extends StackFrame {
  original: OriginalPosition | null;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

/** Un nom de fichier de version acceptable : jamais un chemin. */
export const BUNDLE_FILE = /^[A-Za-z0-9._-]{1,120}\.m?js$/;

/** Les cadres d'une pile V8 ou Firefox/Safari dont la ligne et la colonne sont lisibles. */
export function parseStackFrames(stack: string | null | undefined, max = 30): StackFrame[] {
  if (!stack) return [];
  const out: StackFrame[] = [];
  for (const raw of stack.split('\n')) {
    const line = raw.trim();
    const v8 = /^at\s+(?:(.+?)\s+\()?(\S+?):(\d+):(\d+)\)?$/.exec(line);
    const ff = v8 ? null : /^(?:(.*?)@)?(\S+?):(\d+):(\d+)$/.exec(line);
    const m = v8 ?? ff;
    if (!m) continue;
    const url = m[2];
    const file = url.split(/[?#]/)[0].split('/').pop() ?? '';
    if (!BUNDLE_FILE.test(file)) continue;
    out.push({ fn: m[1] ? m[1].replace(/^(async|new)\s+/, '') : null, url, file, line: Number(m[3]), column: Number(m[4]) });
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Position d'origine d'une position générée (ligne à partir de 1, colonne à
 * partir de 1 comme dans une pile). Le segment retenu est le dernier qui
 * commence avant la colonne. Rend null si la ligne n'a aucun segment.
 */
export function originalPositionFor(map: RawSourceMap, line: number, column: number): OriginalPosition | null {
  if (!map || typeof map.mappings !== 'string' || !Array.isArray(map.sources)) return null;
  const targetLine = line - 1;
  const targetCol = column - 1;
  let genLine = 0;
  let genCol = 0;
  let src = 0;
  let origLine = 0;
  let origCol = 0;
  let name = 0;
  let best: OriginalPosition | null = null;
  const s = map.mappings;
  let i = 0;
  const fields: number[] = [];
  while (i < s.length && genLine <= targetLine) {
    const c = s[i];
    if (c === ';') { genLine++; genCol = 0; i++; continue; }
    if (c === ',') { i++; continue; }
    fields.length = 0;
    while (i < s.length && s[i] !== ',' && s[i] !== ';') {
      let value = 0;
      let shift = 0;
      let cont: boolean;
      do {
        const digit = B64_INDEX.get(s[i++]);
        if (digit === undefined) return best;
        cont = (digit & 32) !== 0;
        value += (digit & 31) << shift;
        shift += 5;
      } while (cont && i < s.length);
      fields.push(value & 1 ? -(value >>> 1) : value >>> 1);
    }
    genCol += fields[0] ?? 0;
    if (fields.length >= 4) {
      src += fields[1];
      origLine += fields[2];
      origCol += fields[3];
      if (fields.length >= 5) name += fields[4];
      if (genLine === targetLine && genCol <= targetCol) {
        const source = map.sources[src];
        best = source === undefined ? null : {
          source: (map.sourceRoot ?? '') + source,
          line: origLine + 1,
          column: origCol + 1,
          name: fields.length >= 5 ? map.names?.[name] ?? null : null,
        };
      }
    }
  }
  return best;
}

/**
 * Chaque cadre avec sa position d'origine. `loadMap` rend la map d'un
 * fichier de la version, ou null ; une map absente laisse le cadre tel quel.
 */
export async function symbolicateStack(
  stack: string | null | undefined,
  loadMap: (file: string) => Promise<RawSourceMap | null>,
): Promise<SymbolicatedFrame[]> {
  const frames = parseStackFrames(stack);
  const cache = new Map<string, Promise<RawSourceMap | null>>();
  const out: SymbolicatedFrame[] = [];
  for (const f of frames) {
    if (!cache.has(f.file)) cache.set(f.file, loadMap(f.file).catch(() => null));
    const map = await cache.get(f.file)!;
    out.push({ ...f, original: map ? originalPositionFor(map, f.line, f.column) : null });
  }
  return out;
}
