# Sentinel

Suivi d'erreurs **extractible**, sur le modèle de RLS Guard : un cœur pur sans
code de l'hôte, un schéma SQL installé dans la base de l'hôte, et une preuve
qui doit réussir **et** échouer. SILLON en est le premier hôte (cockpit,
lot 3, 2026-11-07).

> **Licence : à décider.** Ce dépôt est public mais ne porte pas encore de
> licence : par défaut, tous droits réservés.

## Ce que fait le socle (lot 3)

| Problème constaté dans SILLON | Ce que fait Sentinel |
|---|---|
| « [object Object] » pour toute erreur Supabase | `normalizeError` lit message, code SQLSTATE / PostgREST, détail, indice |
| Rien de global : seules les erreurs attrapées à la main partaient | `createSentinel().install(window)` : `error`, `unhandledrejection`, navigations |
| Le portail toujours « sans boutique » | La boutique PRÉTENDUE est vérifiée en base par le crochet de l'hôte |
| Le jeton d'un lien magique dans l'adresse | Requête et fragment retirés, e-mails / JWT / clés masqués, navigateur PUIS serveur |
| Journal écrit sans compte et sans limite | 64 Ko par événement, 30 / minute par clé, 600 / minute au total ; empreinte recalculée par le serveur |
| 343 lignes isolées | Un problème par empreinte (type + pile de l'application, à défaut message normalisé) |

Le lot 4 ajoutera le cycle de vie (en cours, résolu, ignoré, régression), les
versions et source maps, les écrans, les règles d'alerte et la purge.

## Fichiers

```
src/types.ts        format commun d'un événement (v1) et plafonds
src/scrub.ts        ce qui ne sort jamais : e-mails, jetons, requête, fragment
src/normalize.ts    une erreur de n'importe quelle forme → NormalizedError
src/fingerprint.ts  empreinte stable (FNV-1a 32 bits, identique partout)
src/breadcrumbs.ts  fil des dernières actions
src/event.ts        buildEvent (SDK) et validateEvent (serveur, ne croit rien)
src/browser.ts      SDK navigateur : écoute, dédoublonnage, débit, envoi qui ne lève jamais
src/deno.ts         SDK Deno : withSentinel(handler) pour les edge functions
sql/001_sentinel.sql schéma de référence (problèmes, événements, débit, réception)
test/               la preuve : chaque contrôle a été vu rouge sous sabotage
```

```bash
npm ci && npm run typecheck && npm test
```

Les imports internes portent l'extension `.ts` : le même code tourne sous
Vite, Node et Deno sans réécriture.

## Ce que l'hôte fournit

1. **`public.sentinel_host_tenant(p_claimed uuid, p_user uuid) RETURNS uuid`**,
   défini AVANT le schéma : la boutique de l'événement si l'utilisateur lui
   appartient, sinon NULL. Strictement — jamais la valeur prétendue telle quelle.
2. **Une fonction de réception** qui valide le corps (`validateEvent`), lit
   l'utilisateur dans le jeton VÉRIFIÉ (jamais dans le corps), choisit une clé
   de débit (utilisateur, à défaut empreinte de l'adresse IP) et appelle
   `sentinel_ingest` en service_role.
3. **Le contexte** du SDK : surface d'une adresse, version déployée, jeton de
   session, boutique affichée.

Dans SILLON : migration `20261107160000_sentinel_foundation.sql` (crochet +
ce schéma recopié à l'identique), edge function `sentinel-ingest`,
`src/lib/sentinel-client.ts`.

## Ce dépôt et SILLON

Ce dépôt est la SOURCE. SILLON en garde une copie dans `packages/sentinel`,
puis la recopie à l'identique pour ses edge functions
(`scripts/sentinel-sync.mjs`) et dans sa migration ; ses propres tests
vérifient l'égalité des copies. Une modification se fait ici, puis se reporte
dans SILLON.
