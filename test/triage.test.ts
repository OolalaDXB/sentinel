/**
 * Lot 3 : santé des sessions (anonyme, une fois), identifiant d'événement
 * côté client (retour utilisateur), écoute des erreurs non attrapées.
 */
import { describe, expect, it, vi } from 'vitest';
import { createSentinel, randomId } from '../src/browser.ts';
import { createSessionHealth, type SessionBeat } from '../src/session.ts';
import type { SentinelEvent } from '../src/types.ts';

const flush = () => new Promise((r) => setTimeout(r, 0));
const memoryStorage = () => {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => { m.set(k, v); } };
};

describe('santé des sessions', () => {
  it('une session compte UNE fois par version, même rechargée', async () => {
    const sent: SessionBeat[] = [];
    const storage = memoryStorage();
    const h1 = createSessionHealth({ release: 'v1', surface: () => 'erp', send: (b) => { sent.push(b); }, storage });
    expect(h1.start()).toBe(true);
    expect(h1.start()).toBe(false);
    const reloaded = createSessionHealth({ release: 'v1', surface: () => 'erp', send: (b) => { sent.push(b); }, storage });
    expect(reloaded.start()).toBe(false);
    const nextRelease = createSessionHealth({ release: 'v2', surface: () => 'erp', send: (b) => { sent.push(b); }, storage });
    expect(nextRelease.start()).toBe(true);
    await flush();
    expect(sent.map((b) => `${b.release}:${b.status}`)).toEqual(['v1:start', 'v2:start']);
  });

  it('une session plantée a commencé, et ne plante qu’une fois', async () => {
    const sent: SessionBeat[] = [];
    const h = createSessionHealth({ release: 'v1', surface: () => 'portal', send: (b) => { sent.push(b); }, storage: memoryStorage() });
    expect(h.crashed()).toBe(true);
    expect(h.crashed()).toBe(false);
    await flush();
    expect(sent.map((b) => b.status)).toEqual(['start', 'crashed']);
  });

  it('rien d’identifiant ne part : type, version, surface, statut', async () => {
    const sent: SessionBeat[] = [];
    createSessionHealth({ release: 'v1', surface: () => 'erp', send: (b) => { sent.push(b); }, storage: memoryStorage() }).start();
    await flush();
    expect(Object.keys(sent[0]).sort()).toEqual(['release', 'status', 'surface', 'type']);
  });

  it('stockage refusé, envoi qui lève ou rejette : rien ne lève, rien ne reste en l’air', async () => {
    const rejected: unknown[] = [];
    const on = (e: unknown) => { rejected.push(e); };
    process.on('unhandledRejection', on);
    try {
      const broken = { getItem: () => { throw new Error('quota'); }, setItem: () => { throw new Error('quota'); } };
      const h = createSessionHealth({ release: 'v1', surface: () => 'erp', send: () => Promise.reject(new Error('panne')), storage: broken });
      expect(h.start()).toBe(true);
      expect(h.start()).toBe(false);
      const t = createSessionHealth({ release: 'v1', surface: () => { throw new Error('x'); }, send: () => { throw new Error('y'); }, storage: null });
      expect(() => t.crashed()).not.toThrow();
      for (let i = 0; i < 4; i++) await flush();
    } finally { process.off('unhandledRejection', on); }
    expect(rejected).toEqual([]);
  });
});

describe('identifiant d’événement et erreurs non attrapées', () => {
  it('chaque événement porte un identifiant v4 tiré au hasard, hors de l’empreinte', () => {
    const s = createSentinel({ endpoint: 'x', transport: () => {}, dedupeMs: 0 });
    const a = s.captureException(new Error('même'));
    const b = s.captureException(new Error('même'));
    expect(a?.context.client_event_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(a?.context.client_event_id).not.toBe(b?.context.client_event_id);
    expect(a?.fingerprint).toBe(b?.fingerprint);
    expect(randomId(() => 0.5)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('le repli sans crypto rend aussi un v4', () => {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    try {
      expect(randomId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    } finally {
      if (saved) Object.defineProperty(globalThis, 'crypto', saved);
    }
  });

  it('une erreur non attrapée prévient l’hôte ; un crochet qui lève ne casse rien', () => {
    const listeners: Record<string, (e: Event) => void> = {};
    const target = { addEventListener: (n: string, f: (e: Event) => void) => { listeners[n] = f; }, removeEventListener: () => {}, location: { href: 'https://x/p' } };
    const onUnhandled = vi.fn(() => { throw new Error('crochet en panne'); });
    const events: SentinelEvent[] = [];
    createSentinel({ endpoint: 'x', transport: (e) => { events.push(e); }, onUnhandled }).install(target as never);
    expect(() => listeners.error({ error: new Error('boom') } as unknown as Event)).not.toThrow();
    expect(() => listeners.unhandledrejection({ reason: new Error('rejet') } as unknown as Event)).not.toThrow();
    expect(onUnhandled).toHaveBeenCalledTimes(2);
  });

  it('une capture MANUELLE ne marque pas la session plantée', () => {
    const onUnhandled = vi.fn();
    createSentinel({ endpoint: 'x', transport: () => {}, onUnhandled }).captureException(new Error('attrapée'));
    expect(onUnhandled).not.toHaveBeenCalled();
  });
});
