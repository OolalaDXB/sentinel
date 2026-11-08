# Sentinel

Suivi d'erreurs **extractible**, sur le modèle de RLS Guard : un cœur pur sans
code de l'hôte, un schéma SQL installé dans la base de l'hôte, et une preuve
qui doit réussir **et** échouer. SILLON en est le premier hôte (cockpit,
lot 3, 2026-11-07).

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
src/data.ts         refus de données : objet, opération, code, valeurs expurgées
src/modules/monitors règle d'état d'un moniteur (module facultatif)
sql/003_releases.sql versions, piles lisibles
sql/004_release_purge.sql purge des source maps
sql/005_db_context.sql diagnostic de base au premier événement
sql/006_triage.sql  recherche, attribution, fusion, sourdine, retours, sessions, résumé
sql/007_module_settings.sql interrupteurs des modules
sql/modules/performance/001_performance.sql Web Vitals, requêtes lentes
sql/modules/uptime/001_uptime.sql moniteurs HTTP
sql/modules/uptime/002_purge.sql purge des vérifications (mot de suppression)
sql/modules/guard/001_guard.sql rapports d'un garde de RLS
src/session.ts      battement de session anonyme (santé des versions)
sql/modules/monitors/001_monitors.sql moniteurs de tâches
test/               tests du paquet seul
```

Les imports internes portent l'extension `.ts` : le même code tourne sous
Vite, Node et Deno sans réécriture.

## Contrat de l'hôte

Tout ce qui dépend d'un hôte passe par ces crochets, et par eux seuls. Le
paquet n'en suppose aucun autre ; `sentinel-extractability.test.ts` (dans le
premier hôte) rougit sur un crochet utilisé sans être déclaré ici. Chaque
crochet est une fonction SQL `public`, `SECURITY DEFINER`, sans droit pour
les rôles clients, définie AVANT le schéma qui l'appelle. Une garde rend
strictement vrai ou faux, jamais NULL.

| Crochet | Requis par | Rôle |
|---|---|---|
| `public.sentinel_host_tenant(p_claimed uuid, p_user uuid) RETURNS uuid` | 001 (obligatoire) | le tenant de l'événement si l'utilisateur lui appartient, sinon NULL — jamais la valeur prétendue telle quelle |
| `public.sentinel_host_is_operator() RETURNS boolean` | 002 (obligatoire) | l'appelant courant peut-il trier (strictement vrai ou faux) |
| `public.sentinel_host_alert(p_kind text, p_issue uuid, p_payload jsonb) RETURNS boolean` | 002 (obligatoire) | envoie une alerte par le canal de l'hôte ; vrai si partie ; ne lève jamais. `p_kind` : `new_issue`, `regression`, `frequency`, `weekly` (006) et `guard_block` (module guard), ces deux derniers avec `p_issue` NULL |
| `public.sentinel_host_db_context(p_text text, p_resource text, p_seen_at timestamptz) RETURNS jsonb` | 005 (facultatif) | diagnostic de base d'un problème : règles d'accès, droits, migration qui touche l'objet. Absent ⇒ rien n'est rempli |
| `public.sentinel_host_operators()` → `TABLE (user_id uuid, label text)` | 006 (facultatif) | les exploitants à qui un problème peut être attribué. Absent ⇒ personne n'est désignable |
| `public.sentinel_host_slow_operations(p_since timestamptz)` → `TABLE (operation text, duration_ms integer, at timestamptz, actor_key text, actor_label text)` | module performance (facultatif) | le journal des lenteurs DE L'HÔTE, avec l'acteur ; absent ⇒ « non disponible » |
| `public.sentinel_host_http_request(p_url text, p_timeout_ms integer) RETURNS bigint` | module uptime (facultatif) | part une requête GET SANS attendre et rend sa référence |
| `public.sentinel_host_http_responses(p_refs bigint[])` → `TABLE (ref bigint, status_code integer, error text, timed_out boolean, responded_at timestamptz)` | module uptime (facultatif) | les réponses arrivées : la PREUVE ; absentes une heure ⇒ échec |
| `public.sentinel_host_guard_history()` → `TABLE (source text, verdict text, run_at timestamptz, summary jsonb, run_url text)` | module guard (facultatif) | le dernier verdict de chaque contrôle que l'hôte tenait déjà ; absent ⇒ pas d'historique |
| `public.sentinel_host_monitor_proofs()` → `TABLE (name text, last_success_at timestamptz, last_failure_at timestamptz, last_error text, observed_every_minutes integer)` | module moniteurs | les PREUVES de passage des tâches planifiées. Absent ⇒ le module ne fait rien |

Le schéma 002 utilise aussi `auth.uid()` pour nommer l'auteur d'un geste :
un hôte qui n'a pas ce schéma le définit (rendre NULL suffit).

Côté code, l'hôte fournit :

1. **Une fonction de réception** qui valide le corps (`validateEvent`), lit
   l'utilisateur dans le jeton VÉRIFIÉ (jamais dans le corps), choisit une clé
   de débit (utilisateur, à défaut empreinte de l'adresse IP) et appelle
   `sentinel_ingest` en service_role.
2. **Le contexte** du SDK navigateur : surface d'une adresse, version
   déployée, jeton de session, tenant affiché.
3. **Pour les fonctions serveur** (`withSentinel`, `must`) : un écrivain
   (`write`), un interrupteur (`enabled`), et `defer` pour qu'un envoi
   survive à la réponse. L'enrobage ne change JAMAIS une réponse : il relève
   la même exception, rend le même objet `Response`, n'attend aucun envoi.
4. **Pour les refus de données du navigateur** : un point d'observation des
   réponses du client de base qui appelle `captureDataFailure` — objet,
   opération, statut, code ; jamais une valeur.

## Échecs silencieux (schéma 005 et module moniteurs, lot 2)

| Besoin | Ce que fait Sentinel |
|---|---|
| Un refus d'écriture que personne ne lit | `captureDataFailure` / `must` : empreinte OBJET + OPÉRATION + CODE ; message expurgé de ses valeurs, détail retiré |
| Une écriture qui devait toucher une ligne | `must(…, { expectRows: true })` : code `SENTINEL_NO_ROWS` |
| Une fonction serveur qui rend 5xx sans lever | `withSentinel` l'inscrit, rend la même réponse |
| Savoir quoi corriger côté base | `db_context` posé au premier événement par `sentinel_host_db_context` |
| Une tâche planifiée devenue muette | module `monitors` : retard ou échec ⇒ UN problème `monitor_missed:` / `monitor_failed:` ; « Éprouver » vérifie que l'alerte part |

## Trier comme une équipe (schéma 006, lot 3)

| Besoin | Ce que fait Sentinel |
|---|---|
| Retrouver un problème | `sentinel_issue_search(filtres, curseur, limite)` : texte, statuts, surface, tenant, version, période, « assigné à moi », régressions ouvertes ; curseur `(last_seen_at, id)` ; comptes par statut |
| Se répartir le travail | `sentinel_issue_assign`, `sentinel_issue_comment`, journal `sentinel_issue_activity` |
| Deux empreintes, un seul défaut | `sentinel_issue_merge(source, cible)` : alias d'empreinte ; les événements à venir vont à la cible ; `sentinel_issue_unmerge` rend l'état d'avant ; ni chaîne ni cycle |
| Faire taire un bruit connu | `sentinel_issue_mute(problème, jusqu'au, N événements)` ; compté, jamais alerté ; une régression lève la sourdine |
| Santé d'une version | `createSessionHealth` (navigateur) : un battement ANONYME par session et par version, « crashed » sur erreur non attrapée ; `sentinel_release_health` : taux sans plantage, NULL sans session |
| Ce que l'utilisateur faisait | chaque événement porte `context.client_event_id` (tiré au hasard) ; `sentinel_feedback_submit` rattache un retour à CET événement, une fois, dans l'heure |
| La semaine en une lecture | `sentinel_weekly_digest(fuseau, heure)` : le lundi, une fois, par `sentinel_host_alert('weekly', …)` ; interrupteur `weekly_digest` |

La réception version 6 résout les alias et applique la sourdine. Aucune
fonction ne supprime : défaire une fusion désactive l'alias.

## Modules

Un module est FACULTATIF : `src/modules/<nom>/` (règle pure, alias
`@sentinel/<nom>` chez l'hôte) et `sql/modules/<nom>/` (schéma). Le cœur ne
l'importe jamais ; absent, rien ne casse. Interrupteur en base :
`sentinel_settings` (clé du module), éteint par défaut.

- `monitors` — tâches muettes (lot 2).
- `performance` — Web Vitals par route et version (histogramme de classes de
  10 %, p50 / p75 / p95, régression du p75 au-delà de +20 %), requêtes lentes
  lues chez l'hôte avec leur acteur (lot 4). `collectWebVitals`,
  `normalizeRoute` ; interrupteur `vitals_check`.
- `uptime` — moniteurs HTTP : la preuve est la réponse, N échecs d'affilée ⇒
  problème `uptime_down`, rétabli ⇒ résolu (lot 4). Interrupteur `http_monitors`.
  Schéma 002 : `sentinel_http_checks_purge(jours)`, 30 jours au moins — il
  contient un mot de suppression, à poser sous l'enveloppe de l'hôte (lot 5).
- `guard` — les rapports d'un garde de RLS, au format EXACT
  `rls-guard-evidence/1` (lot 5). Le module ne lit que cette SORTIE, il
  n'importe rien de l'outil. Une erreur (code 2) s'inscrit `error`, jamais
  `pass` ; `not-run` n'est jamais un succès ; une violation, sans identifiant,
  a pour empreinte invariant + texte normalisé ; nouvelle, revenue ou résolue
  puis présente ⇒ problème `guard_finding:` ; disparue ⇒ « absente depuis »,
  jamais résolue d'office ; bloquant ⇒ `sentinel_host_alert('guard_block')`.
  `parseGuardSubmission` refuse tôt ; la base revérifie tout.

## Tests

`npx vitest run packages/sentinel` : tests du paquet seul, imports relatifs.

## Mettre à jour

Modifier le dépôt `sentinel`, puis recopier ici `src/`, `sql/` et `test/`,
lancer `npm run sync:sentinel` et reporter chaque nouveau fichier `sql/…`
entre les marqueurs `sentinel:sql:<nom>` d'une nouvelle migration : les tests
de l'hôte vérifient l'égalité.
