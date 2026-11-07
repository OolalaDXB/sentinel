# Sentinel

Suivi d'erreurs **extractible**, sur le modèle de RLS Guard : un cœur pur sans
code de l'hôte, un schéma SQL installé dans la base de l'hôte, et une preuve
qui doit réussir **et** échouer. SILLON en est le premier hôte (cockpit,
lot 3, 2026-11-07).

Licence : [Apache-2.0](LICENSE).

## Ce que fait le socle (lot 3)

| Problème constaté dans SILLON | Ce que fait Sentinel |
|---|---|
| « [object Object] » pour toute erreur Supabase | `normalizeError` lit message, code SQLSTATE / PostgREST, détail, indice |
| Rien de global : seules les erreurs attrapées à la main partaient | `createSentinel().install(window)` : `error`, `unhandledrejection`, navigations |
| Le portail toujours « sans boutique » | La boutique PRÉTENDUE est vérifiée en base par le crochet de l'hôte |
| Le jeton d'un lien magique dans l'adresse | Requête et fragment retirés, e-mails / JWT / clés masqués, navigateur PUIS serveur |
| Journal écrit sans compte et sans limite | 64 Ko par événement, 30 / minute par clé, 600 / minute au total ; empreinte recalculée par le serveur |
| 343 lignes isolées | Un problème par empreinte (type + pile de l'application, à défaut message normalisé) |

## Exploitation (schéma 002, lot 4a)

| Besoin | Ce que fait Sentinel |
|---|---|
| Trier | non résolu → en cours → résolu / ignoré (`sentinel_set_issue_status`) ; ignorer exige un motif ; historique avec l'auteur |
| Voir revenir | un résolu qui revient redevient non résolu : RÉGRESSION comptée, inscrite, alertée ; un ignoré n'alerte jamais |
| Être prévenu | trois règles (`new_issue`, `regression`, `frequency`), plafond de 10 alertes par heure, résultat inscrit (`sentinel_alerts`) |
| Ne pas tout garder | `sentinel_purge(jours)` : événements de plus de N jours (30 au moins) ; problèmes et historique restent |
| Lire | `sentinel_issue_list`, `sentinel_issue_detail`, `sentinel_alert_rules_list` : exploitant seul |

## Versions et source maps (schéma 003, lot 4b)

`sourcemap.ts` lit une pile minifiée avec la source map de SA version
(`parseStackFrames`, `originalPositionFor`, `symbolicateStack`), sans
dépendance. `isMinifiedName` écarte de l'empreinte les noms du minifieur, qui
changent à chaque build. `003_releases.sql` : `sentinel_releases` (inscrite par
le service), `sentinel_release_list` et `sentinel_event_stack` (exploitant).
L'hôte garde les maps à part, jamais servies au public.


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
src/lifecycle.ts    statuts, gestes proposés, règles d'alerte
sql/001_sentinel.sql schéma de référence (problèmes, événements, débit, réception)
sql/002_lifecycle.sql cycle de vie, régressions, règles d'alerte, purge
src/sourcemap.ts    lire une pile minifiée avec sa source map
sql/003_releases.sql versions, piles lisibles
test/               la preuve : chaque contrôle a été vu rouge sous sabotage
```

```bash
npm ci && npm run typecheck && npm test
```

Les imports internes portent l'extension `.ts` : le même code tourne sous
Vite, Node et Deno sans réécriture.

## Ce que l'hôte fournit

0. **Schéma 002** : **`public.sentinel_host_is_operator() RETURNS boolean`**
   (qui peut trier — strictement vrai ou faux) et
   **`public.sentinel_host_alert(p_kind text, p_issue uuid, p_payload jsonb) RETURNS boolean`**
   (l'envoi d'une alerte par le canal de l'hôte), définis AVANT `002_lifecycle.sql`.
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
