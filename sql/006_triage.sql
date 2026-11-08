-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — trier comme une équipe (version 6).
--
-- Recherche en base (texte, statut, surface, tenant, version, période,
-- « assigné à moi », curseur), attribution, commentaires et journal
-- d'activité, FUSION de problèmes par alias d'empreinte (réversible),
-- SOURDINE jusqu'à une date ou N événements (une régression la lève), RETOUR
-- utilisateur rattaché à son événement, santé des versions par compteurs de
-- sessions ANONYMES, résumé hebdomadaire.
--
-- Crochet de l'hôte, en plus de ceux des versions 1 et 2 :
--   public.sentinel_host_operators() RETURNS TABLE (user_id uuid, label text)
--     les exploitants à qui un problème peut être attribué.
-- Réception, version 6 : la 2, plus la résolution des alias et la sourdine.
-- Aucun mot de suppression : défaire une fusion désactive l'alias.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS assignee uuid;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS assigned_at timestamptz;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS merged_into uuid REFERENCES public.sentinel_issues(id);
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS merged_at timestamptz;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS muted_at timestamptz;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS muted_by uuid;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS muted_until timestamptz;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS muted_until_count bigint;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS mute_note text;
CREATE INDEX IF NOT EXISTS sentinel_issues_merged_into_idx ON public.sentinel_issues (merged_into);
CREATE INDEX IF NOT EXISTS sentinel_issues_assignee_idx ON public.sentinel_issues (assignee);

CREATE TABLE IF NOT EXISTS public.sentinel_issue_aliases (
  fingerprint text PRIMARY KEY,
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  source_issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  active boolean NOT NULL DEFAULT true,
  merged_at timestamptz NOT NULL DEFAULT now(),
  merged_by uuid,
  unmerged_at timestamptz,
  unmerged_by uuid
);
CREATE INDEX IF NOT EXISTS sentinel_issue_aliases_issue_idx ON public.sentinel_issue_aliases (issue_id);
CREATE INDEX IF NOT EXISTS sentinel_issue_aliases_source_idx ON public.sentinel_issue_aliases (source_issue_id);

CREATE TABLE IF NOT EXISTS public.sentinel_issue_comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  author uuid,
  body text NOT NULL CHECK (length(btrim(body)) BETWEEN 1 AND 4000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sentinel_issue_comments_issue_idx ON public.sentinel_issue_comments (issue_id, created_at);

CREATE TABLE IF NOT EXISTS public.sentinel_issue_activity (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  at timestamptz NOT NULL DEFAULT now(),
  actor uuid,
  kind text NOT NULL CHECK (kind IN ('assigned', 'unassigned', 'commented', 'merged', 'unmerged', 'absorbed', 'released', 'muted', 'unmuted', 'mute_lifted', 'feedback')),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS sentinel_issue_activity_issue_idx ON public.sentinel_issue_activity (issue_id, at DESC);

-- Retour utilisateur : rattaché au problème ; l'événement est désigné par son
-- identifiant SANS clé étrangère (la purge retire les événements, jamais le retour).
CREATE TABLE IF NOT EXISTS public.sentinel_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  event_id uuid NOT NULL,
  user_id uuid,
  message text NOT NULL CHECK (length(btrim(message)) BETWEEN 1 AND 1000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sentinel_feedback_issue_idx ON public.sentinel_feedback (issue_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS sentinel_feedback_event_uniq ON public.sentinel_feedback (event_id);

-- Santé des versions : des COMPTEURS, aucun identifiant de session ni de personne.
CREATE TABLE IF NOT EXISTS public.sentinel_session_counts (
  release text NOT NULL,
  day date NOT NULL,
  surface text NOT NULL CHECK (surface IN ('erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown')),
  sessions bigint NOT NULL DEFAULT 0,
  crashed bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (release, day, surface)
);

CREATE TABLE IF NOT EXISTS public.sentinel_weekly_digests (
  week_start date PRIMARY KEY,
  sent_at timestamptz NOT NULL DEFAULT now(),
  dispatched boolean NOT NULL,
  payload jsonb NOT NULL
);

ALTER TABLE public.sentinel_issue_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_issue_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_issue_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_session_counts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_weekly_digests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_issue_aliases, public.sentinel_issue_comments, public.sentinel_issue_activity,
  public.sentinel_feedback, public.sentinel_session_counts, public.sentinel_weekly_digests FROM PUBLIC, anon, authenticated;

-- L'empreinte qui reçoit l'événement : celle du problème cible si l'empreinte
-- reçue est un alias actif, sinon elle-même.
CREATE OR REPLACE FUNCTION public._sentinel_resolve_fingerprint(p_fingerprint text)
 RETURNS text
 LANGUAGE sql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT coalesce((SELECT i.fingerprint FROM public.sentinel_issue_aliases a
                     JOIN public.sentinel_issues i ON i.id = a.issue_id
                    WHERE a.fingerprint = p_fingerprint AND a.active), p_fingerprint)
$function$;
REVOKE ALL ON FUNCTION public._sentinel_resolve_fingerprint(text) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.sentinel_ingest(p_event jsonb, p_rate_key text, p_user uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_err jsonb := p_event->'error';
  v_fingerprint text := p_event->>'fingerprint';
  v_surface text := coalesce(p_event->>'surface', 'unknown');
  v_type text := v_err->>'type';
  v_message text := v_err->>'message';
  v_release text := p_event->>'release';
  v_claimed uuid;
  v_tenant uuid;
  v_issue public.sentinel_issues%ROWTYPE;
  v_new boolean := false;
  v_regressed boolean := false;
  v_event uuid;
  v_rule public.sentinel_alert_rules%ROWTYPE;
  v_payload jsonb;
  v_muted boolean := false;
  v_lift text;
BEGIN
  IF p_event IS NULL OR v_err IS NULL OR v_fingerprint IS NULL OR v_message IS NULL
     OR length(v_fingerprint) > 64 OR length(v_message) > 1000
     OR v_surface NOT IN ('erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown')
     OR v_type IS NULL OR v_type NOT IN ('permission_denied', 'database', 'edge_function', 'network', 'render', 'javascript', 'unknown')
     OR length(p_event::text) > 65536 THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'INVALID');
  END IF;

  -- Plafond par clé (30 / minute) puis plafond global (600 / minute).
  IF public.sentinel_rate_hit('key:' || coalesce(p_rate_key, 'none'), 30)
     OR public.sentinel_rate_hit('global', 600) THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'RATE_LIMITED');
  END IF;

  -- Version 6 : une empreinte FUSIONNÉE va au problème cible.
  v_fingerprint := public._sentinel_resolve_fingerprint(v_fingerprint);

  BEGIN
    v_claimed := nullif(p_event->>'claimed_tenant', '')::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    v_claimed := NULL;
  END;
  v_tenant := public.sentinel_host_tenant(v_claimed, p_user);

  INSERT INTO public.sentinel_issues (fingerprint, error_type, title, code, first_release, last_release, surfaces, event_count)
  VALUES (v_fingerprint, v_type, left(v_message, 200), v_err->>'code', v_release, v_release, ARRAY[v_surface], 0)
  ON CONFLICT (fingerprint) DO NOTHING
  RETURNING * INTO v_issue;
  v_new := FOUND;
  -- Verrou de la ligne : deux événements simultanés d'un problème résolu ne
  -- font qu'UNE régression.
  SELECT * INTO v_issue FROM public.sentinel_issues WHERE fingerprint = v_fingerprint FOR UPDATE;

  IF v_issue.status = 'resolved' THEN
    v_regressed := true;
    INSERT INTO public.sentinel_issue_history (issue_id, from_status, to_status, actor, reason, release)
    VALUES (v_issue.id, 'resolved', 'unresolved', NULL, 'regression', v_release);
  END IF;

  UPDATE public.sentinel_issues i
     SET last_seen_at = now(),
         event_count = i.event_count + 1,
         last_release = coalesce(v_release, i.last_release),
         surfaces = CASE WHEN v_surface = ANY (i.surfaces) THEN i.surfaces ELSE i.surfaces || v_surface END,
         status = CASE WHEN v_regressed THEN 'unresolved' ELSE i.status END,
         regression_count = i.regression_count + CASE WHEN v_regressed THEN 1 ELSE 0 END,
         last_regressed_at = CASE WHEN v_regressed THEN now() ELSE i.last_regressed_at END,
         status_changed_at = CASE WHEN v_regressed THEN now() ELSE i.status_changed_at END,
         status_changed_by = CASE WHEN v_regressed THEN NULL ELSE i.status_changed_by END,
         status_note = CASE WHEN v_regressed THEN NULL ELSE i.status_note END
   WHERE i.id = v_issue.id
  RETURNING * INTO v_issue;

  -- Sourdine (version 6) : une régression la lève ; « N événements » se lève
  -- au N-ième ; une date passée se lève à l'événement suivant.
  IF v_issue.muted_at IS NOT NULL THEN
    v_lift := CASE
      WHEN v_regressed THEN 'regression'
      WHEN v_issue.muted_until_count IS NOT NULL AND v_issue.event_count >= v_issue.muted_until_count THEN 'count'
      WHEN v_issue.muted_until IS NOT NULL AND v_issue.muted_until <= now() THEN 'date'
    END;
    IF v_lift IS NULL THEN
      v_muted := true;
    ELSE
      UPDATE public.sentinel_issues
         SET muted_at = NULL, muted_by = NULL, muted_until = NULL, muted_until_count = NULL, mute_note = NULL
       WHERE id = v_issue.id
      RETURNING * INTO v_issue;
      INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload)
      VALUES (v_issue.id, NULL, 'mute_lifted', jsonb_build_object('reason', v_lift, 'release', v_release));
    END IF;
  END IF;

  INSERT INTO public.sentinel_events (
    issue_id, occurred_at, release, environment, surface, error_type, error_name, message,
    code, details, hint, stack, url, tenant_id, user_id, breadcrumbs, context)
  VALUES (
    v_issue.id,
    coalesce(nullif(p_event->>'occurred_at', '')::timestamptz, now()),
    v_release,
    coalesce(p_event->>'environment', 'production'),
    v_surface, v_type, v_err->>'name', v_message,
    v_err->>'code', v_err->>'details', v_err->>'hint', v_err->>'stack',
    p_event->>'url', v_tenant, p_user,
    CASE WHEN jsonb_typeof(p_event->'breadcrumbs') = 'array' THEN p_event->'breadcrumbs' ELSE '[]'::jsonb END,
    CASE WHEN jsonb_typeof(p_event->'context') = 'object' THEN p_event->'context' ELSE '{}'::jsonb END)
  RETURNING id INTO v_event;

  v_payload := jsonb_build_object(
    'issue_id', v_issue.id, 'title', v_issue.title, 'error_type', v_issue.error_type, 'code', v_issue.code,
    'surface', v_surface, 'url', p_event->>'url', 'release', v_release, 'tenant_id', v_tenant,
    'event_count', v_issue.event_count, 'regression_count', v_issue.regression_count,
    'resolved_release', v_issue.resolved_release,
    'stack_excerpt', left(coalesce(v_err->>'stack', ''), 800));
  IF v_muted THEN
    NULL;  -- En sourdine : compté, jamais alerté.
  ELSIF v_new THEN
    PERFORM public._sentinel_alert('new_issue', v_issue.id, v_payload);
  ELSIF v_regressed THEN
    PERFORM public._sentinel_alert('regression', v_issue.id, v_payload);
  ELSE
    SELECT * INTO v_rule FROM public.sentinel_alert_rules WHERE kind = 'frequency';
    IF FOUND AND v_rule.enabled AND (
      SELECT count(*) FROM public.sentinel_events
       WHERE issue_id = v_issue.id AND received_at > now() - make_interval(mins => v_rule.window_minutes)
    ) >= v_rule.threshold THEN
      PERFORM public._sentinel_alert('frequency', v_issue.id,
        v_payload || jsonb_build_object('threshold', v_rule.threshold, 'window_minutes', v_rule.window_minutes));
    END IF;
  END IF;

  RETURN jsonb_build_object('accepted', true, 'issue_id', v_issue.id, 'event_id', v_event,
    'new_issue', v_new, 'regression', v_regressed, 'tenant_id', v_tenant, 'muted', v_muted);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_ingest(jsonb, text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_ingest(jsonb, text, uuid) TO service_role;

-- L'exploitant désigné existe-t-il chez l'hôte ? (strictement vrai ou faux)
CREATE OR REPLACE FUNCTION public._sentinel_is_assignable(p_user uuid)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  IF p_user IS NULL OR to_regprocedure('public.sentinel_host_operators()') IS NULL THEN
    RETURN false;
  END IF;
  RETURN coalesce((SELECT true FROM public.sentinel_host_operators() o WHERE o.user_id = p_user LIMIT 1), false);
END;
$function$;
REVOKE ALL ON FUNCTION public._sentinel_is_assignable(uuid) FROM PUBLIC, anon, authenticated;

-- Recherche (exploitant). Filtres : q, statuses[], surface, tenant, release,
-- since, until, assigned ('me' | 'none' | 'any'), regressed (ouverts revenus
-- après résolution), include_merged. Comptes : par statut, plus `regressed`,
-- calculés SANS les filtres de statut ni de régression. Curseur :
-- { last_seen_at, id } du dernier problème rendu ; tri du plus récent.
CREATE OR REPLACE FUNCTION public.sentinel_issue_search(p_filters jsonb DEFAULT '{}'::jsonb, p_cursor jsonb DEFAULT NULL, p_limit integer DEFAULT 50)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  f jsonb := coalesce(p_filters, '{}'::jsonb);
  v_q text := nullif(btrim(f->>'q'), '');
  v_statuses text[] := CASE WHEN jsonb_typeof(f->'statuses') = 'array'
                            THEN ARRAY(SELECT jsonb_array_elements_text(f->'statuses')) END;
  v_surface text := nullif(f->>'surface', '');
  v_tenant uuid;
  v_release text := nullif(btrim(f->>'release'), '');
  v_since timestamptz;
  v_until timestamptz;
  v_assigned text := coalesce(nullif(f->>'assigned', ''), 'any');
  v_merged boolean := coalesce((f->>'include_merged')::boolean, false);
  v_regressed boolean := coalesce((f->>'regressed')::boolean, false);
  v_limit integer := greatest(1, least(coalesce(p_limit, 50), 200));
  v_c_at timestamptz;
  v_c_id uuid;
  v_me uuid := auth.uid();
  v_items jsonb;
  v_counts jsonb;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  BEGIN
    v_tenant := nullif(f->>'tenant', '')::uuid;
    v_since := nullif(f->>'since', '')::timestamptz;
    v_until := nullif(f->>'until', '')::timestamptz;
    v_c_at := nullif(p_cursor->>'last_seen_at', '')::timestamptz;
    v_c_id := nullif(p_cursor->>'id', '')::uuid;
  EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow THEN
    RAISE EXCEPTION 'SENTINEL_FILTER_INVALID' USING ERRCODE = '22023';
  END;
  IF v_assigned NOT IN ('any', 'me', 'none') THEN
    RAISE EXCEPTION 'SENTINEL_FILTER_INVALID' USING ERRCODE = '22023';
  END IF;

  WITH hits AS (
    SELECT i.*
      FROM public.sentinel_issues i
     WHERE (v_merged OR i.merged_into IS NULL)
       AND (v_q IS NULL OR i.title ILIKE '%' || v_q || '%' OR i.fingerprint ILIKE v_q || '%' OR i.code ILIKE v_q)
       AND (v_surface IS NULL OR v_surface = ANY (i.surfaces))
       AND (v_since IS NULL OR i.last_seen_at >= v_since)
       AND (v_until IS NULL OR i.first_seen_at <= v_until)
       AND (v_assigned = 'any' OR (v_assigned = 'me' AND i.assignee = v_me) OR (v_assigned = 'none' AND i.assignee IS NULL))
       AND (v_release IS NULL OR i.first_release = v_release OR i.last_release = v_release
            OR EXISTS (SELECT 1 FROM public.sentinel_events e WHERE e.issue_id = i.id AND e.release = v_release))
       AND (v_tenant IS NULL OR EXISTS (SELECT 1 FROM public.sentinel_events e WHERE e.issue_id = i.id AND e.tenant_id = v_tenant))
  )
  SELECT
    (SELECT coalesce(jsonb_object_agg(c.status, c.n), '{}'::jsonb)
             || jsonb_build_object('regressed', (SELECT count(*) FROM hits h
                                                 WHERE h.status IN ('unresolved', 'in_progress') AND h.regression_count > 0))
       FROM (SELECT h.status, count(*) AS n FROM hits h GROUP BY h.status) c),
    (SELECT coalesce(jsonb_agg(row_to_json(x) ORDER BY x.last_seen_at DESC, x.id DESC), '[]'::jsonb)
       FROM (
         SELECT h.id, h.fingerprint, h.error_type, h.title, h.code, h.status, h.first_seen_at, h.last_seen_at,
                h.event_count, h.first_release, h.last_release, h.surfaces, h.status_changed_at, h.status_note,
                h.resolved_release, h.regression_count, h.last_regressed_at,
                h.assignee, h.merged_into, h.muted_at, h.muted_until, h.muted_until_count,
                (SELECT count(*) FROM public.sentinel_issue_aliases a WHERE a.issue_id = h.id AND a.active) AS merged_count,
                (SELECT count(DISTINCT e.user_id) FROM public.sentinel_events e WHERE e.issue_id = h.id) AS users_affected,
                (SELECT count(DISTINCT e.tenant_id) FROM public.sentinel_events e WHERE e.issue_id = h.id) AS tenants_affected,
                (SELECT count(*) FROM public.sentinel_events e WHERE e.issue_id = h.id AND e.received_at > now() - interval '24 hours') AS events_24h
           FROM hits h
          WHERE (v_statuses IS NULL OR h.status = ANY (v_statuses))
            AND (NOT v_regressed OR (h.status IN ('unresolved', 'in_progress') AND h.regression_count > 0))
            AND (v_c_at IS NULL OR (h.last_seen_at, h.id) < (v_c_at, v_c_id))
          ORDER BY h.last_seen_at DESC, h.id DESC
          LIMIT v_limit + 1) x)
    INTO v_counts, v_items;

  RETURN jsonb_build_object(
    'items', (SELECT coalesce(jsonb_agg(e), '[]'::jsonb) FROM (SELECT e FROM jsonb_array_elements(v_items) WITH ORDINALITY t(e, n) WHERE n <= v_limit ORDER BY n) z),
    'next_cursor', CASE WHEN jsonb_array_length(v_items) > v_limit
                        THEN jsonb_build_object('last_seen_at', v_items->(v_limit - 1)->>'last_seen_at', 'id', v_items->(v_limit - 1)->>'id') END,
    'counts', v_counts);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_search(jsonb, jsonb, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_search(jsonb, jsonb, integer) TO authenticated;

-- Attribuer (exploitant) ; NULL retire l'attribution. Seul un exploitant de l'hôte est désignable.
CREATE OR REPLACE FUNCTION public.sentinel_issue_assign(p_issue uuid, p_assignee uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_prev uuid;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT assignee INTO v_prev FROM public.sentinel_issues WHERE id = p_issue FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_ISSUE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF p_assignee IS NOT NULL AND NOT public._sentinel_is_assignable(p_assignee) THEN
    RAISE EXCEPTION 'SENTINEL_ASSIGNEE_INVALID' USING ERRCODE = '22023';
  END IF;
  IF p_assignee IS NOT DISTINCT FROM v_prev THEN
    RETURN jsonb_build_object('changed', false, 'assignee', v_prev);
  END IF;
  UPDATE public.sentinel_issues SET assignee = p_assignee, assigned_at = CASE WHEN p_assignee IS NULL THEN NULL ELSE now() END
   WHERE id = p_issue;
  INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload)
  VALUES (p_issue, auth.uid(), CASE WHEN p_assignee IS NULL THEN 'unassigned' ELSE 'assigned' END,
          jsonb_build_object('from', v_prev, 'to', p_assignee));
  RETURN jsonb_build_object('changed', true, 'assignee', p_assignee);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_assign(uuid, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_assign(uuid, uuid) TO authenticated;

-- Commenter (exploitant).
CREATE OR REPLACE FUNCTION public.sentinel_issue_comment(p_issue uuid, p_body text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_id uuid;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.sentinel_issues WHERE id = p_issue) THEN
    RAISE EXCEPTION 'SENTINEL_ISSUE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF p_body IS NULL OR length(btrim(p_body)) = 0 OR length(p_body) > 4000 THEN
    RAISE EXCEPTION 'SENTINEL_COMMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.sentinel_issue_comments (issue_id, author, body) VALUES (p_issue, auth.uid(), btrim(p_body))
  RETURNING id INTO v_id;
  INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload)
  VALUES (p_issue, auth.uid(), 'commented', jsonb_build_object('comment_id', v_id));
  RETURN v_id;
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_comment(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_comment(uuid, text) TO authenticated;

-- Fusionner la SOURCE dans la CIBLE (exploitant) : les événements à venir de
-- l'empreinte source vont à la cible ; ceux déjà reçus restent sur la source,
-- pour que défaire la fusion rende exactement l'état d'avant. Ni chaîne ni
-- cycle : la cible n'est fusionnée nulle part, la source n'est la cible de personne.
CREATE OR REPLACE FUNCTION public.sentinel_issue_merge(p_source uuid, p_target uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  s public.sentinel_issues%ROWTYPE;
  t public.sentinel_issues%ROWTYPE;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  IF p_source IS NULL OR p_target IS NULL OR p_source = p_target THEN
    RAISE EXCEPTION 'SENTINEL_MERGE_INVALID' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO s FROM public.sentinel_issues WHERE id = p_source FOR UPDATE;
  SELECT * INTO t FROM public.sentinel_issues WHERE id = p_target FOR UPDATE;
  IF s.id IS NULL OR t.id IS NULL THEN
    RAISE EXCEPTION 'SENTINEL_ISSUE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF s.merged_into IS NOT NULL OR t.merged_into IS NOT NULL THEN
    RAISE EXCEPTION 'SENTINEL_MERGE_ALREADY_MERGED' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (SELECT 1 FROM public.sentinel_issue_aliases WHERE issue_id = p_source AND active) THEN
    RAISE EXCEPTION 'SENTINEL_MERGE_SOURCE_IS_TARGET' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.sentinel_issue_aliases (fingerprint, issue_id, source_issue_id, active, merged_at, merged_by, unmerged_at, unmerged_by)
  VALUES (s.fingerprint, t.id, s.id, true, now(), auth.uid(), NULL, NULL)
  ON CONFLICT (fingerprint) DO UPDATE
     SET issue_id = EXCLUDED.issue_id, source_issue_id = EXCLUDED.source_issue_id, active = true,
         merged_at = now(), merged_by = auth.uid(), unmerged_at = NULL, unmerged_by = NULL;
  UPDATE public.sentinel_issues SET merged_into = t.id, merged_at = now() WHERE id = s.id;
  INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload) VALUES
    (s.id, auth.uid(), 'merged', jsonb_build_object('into', t.id)),
    (t.id, auth.uid(), 'absorbed', jsonb_build_object('from', s.id, 'fingerprint', s.fingerprint));
  RETURN jsonb_build_object('merged', true, 'source', s.id, 'target', t.id);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_merge(uuid, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_merge(uuid, uuid) TO authenticated;

-- Défaire une fusion (exploitant) : l'alias est désactivé, la source redevient elle-même.
CREATE OR REPLACE FUNCTION public.sentinel_issue_unmerge(p_source uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  s public.sentinel_issues%ROWTYPE;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO s FROM public.sentinel_issues WHERE id = p_source FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_ISSUE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF s.merged_into IS NULL THEN
    RETURN jsonb_build_object('unmerged', false);
  END IF;
  UPDATE public.sentinel_issue_aliases SET active = false, unmerged_at = now(), unmerged_by = auth.uid()
   WHERE fingerprint = s.fingerprint AND active;
  UPDATE public.sentinel_issues SET merged_into = NULL, merged_at = NULL WHERE id = s.id;
  INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload) VALUES
    (s.id, auth.uid(), 'unmerged', jsonb_build_object('from', s.merged_into)),
    (s.merged_into, auth.uid(), 'released', jsonb_build_object('source', s.id));
  RETURN jsonb_build_object('unmerged', true, 'target', s.merged_into);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_unmerge(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_unmerge(uuid) TO authenticated;

-- Sourdine (exploitant) : jusqu'à une date (365 jours au plus) OU jusqu'à N
-- événements de plus. Les deux NULL : la sourdine est levée.
CREATE OR REPLACE FUNCTION public.sentinel_issue_mute(p_issue uuid, p_until timestamptz, p_count integer, p_note text DEFAULT NULL)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  i public.sentinel_issues%ROWTYPE;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO i FROM public.sentinel_issues WHERE id = p_issue FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_ISSUE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF p_until IS NULL AND p_count IS NULL THEN
    UPDATE public.sentinel_issues SET muted_at = NULL, muted_by = NULL, muted_until = NULL, muted_until_count = NULL, mute_note = NULL
     WHERE id = p_issue;
    IF i.muted_at IS NOT NULL THEN
      INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind) VALUES (p_issue, auth.uid(), 'unmuted');
    END IF;
    RETURN jsonb_build_object('muted', false);
  END IF;
  IF (p_until IS NOT NULL AND p_count IS NOT NULL)
     OR (p_until IS NOT NULL AND (p_until <= now() OR p_until > now() + interval '365 days'))
     OR (p_count IS NOT NULL AND (p_count < 1 OR p_count > 1000000)) THEN
    RAISE EXCEPTION 'SENTINEL_MUTE_INVALID' USING ERRCODE = '22023';
  END IF;
  UPDATE public.sentinel_issues
     SET muted_at = now(), muted_by = auth.uid(), muted_until = p_until,
         muted_until_count = CASE WHEN p_count IS NULL THEN NULL ELSE i.event_count + p_count END,
         mute_note = left(nullif(btrim(p_note), ''), 500)
   WHERE id = p_issue;
  INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload)
  VALUES (p_issue, auth.uid(), 'muted', jsonb_build_object('until', p_until, 'events', p_count));
  RETURN jsonb_build_object('muted', true);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_mute(uuid, timestamptz, integer, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_mute(uuid, timestamptz, integer, text) TO authenticated;

-- Le volet de tri d'un problème (exploitant) : attribution, exploitants,
-- commentaires, activité, fusions, sourdine, retours des utilisateurs.
CREATE OR REPLACE FUNCTION public.sentinel_issue_triage(p_issue uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  i public.sentinel_issues%ROWTYPE;
  v_ops jsonb := '[]'::jsonb;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO i FROM public.sentinel_issues WHERE id = p_issue;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF to_regprocedure('public.sentinel_host_operators()') IS NOT NULL THEN
    SELECT coalesce(jsonb_agg(jsonb_build_object('user_id', o.user_id, 'label', o.label) ORDER BY o.label), '[]'::jsonb)
      INTO v_ops FROM public.sentinel_host_operators() o;
  END IF;
  RETURN jsonb_build_object(
    'me', auth.uid(),
    'assignee', i.assignee, 'assigned_at', i.assigned_at,
    'operators', v_ops,
    'merged_into', i.merged_into, 'merged_at', i.merged_at,
    'merged_into_title', (SELECT t.title FROM public.sentinel_issues t WHERE t.id = i.merged_into),
    'absorbed', coalesce((SELECT jsonb_agg(jsonb_build_object('issue_id', a.source_issue_id, 'fingerprint', a.fingerprint,
                                   'title', s.title, 'merged_at', a.merged_at) ORDER BY a.merged_at DESC)
                            FROM public.sentinel_issue_aliases a JOIN public.sentinel_issues s ON s.id = a.source_issue_id
                           WHERE a.issue_id = i.id AND a.active), '[]'::jsonb),
    'mute', CASE WHEN i.muted_at IS NULL THEN NULL ELSE jsonb_build_object(
              'at', i.muted_at, 'by', i.muted_by, 'until', i.muted_until,
              'until_count', i.muted_until_count, 'event_count', i.event_count, 'note', i.mute_note) END,
    'comments', coalesce((SELECT jsonb_agg(jsonb_build_object('id', c.id, 'author', c.author, 'body', c.body, 'created_at', c.created_at) ORDER BY c.created_at)
                            FROM public.sentinel_issue_comments c WHERE c.issue_id = i.id), '[]'::jsonb),
    'activity', coalesce((SELECT jsonb_agg(jsonb_build_object('at', a.at, 'actor', a.actor, 'kind', a.kind, 'payload', a.payload) ORDER BY a.at DESC)
                            FROM (SELECT * FROM public.sentinel_issue_activity WHERE issue_id = i.id ORDER BY at DESC LIMIT 50) a), '[]'::jsonb),
    'feedback', coalesce((SELECT jsonb_agg(jsonb_build_object('id', f.id, 'event_id', f.event_id, 'message', f.message, 'created_at', f.created_at, 'signed_in', f.user_id IS NOT NULL) ORDER BY f.created_at DESC)
                            FROM (SELECT * FROM public.sentinel_feedback WHERE issue_id = i.id ORDER BY created_at DESC LIMIT 50) f), '[]'::jsonb));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_triage(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_triage(uuid) TO authenticated;

-- Battement de session (service seul, appelé par la fonction de réception de
-- l'hôte) : « start » compte une session, « crashed » une session plantée.
-- Rien d'identifiant n'est reçu ni gardé.
CREATE OR REPLACE FUNCTION public.sentinel_session_beat(p_release text, p_surface text, p_status text, p_rate_key text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_release text := coalesce(nullif(btrim(p_release), ''), '');
  v_surface text := coalesce(nullif(p_surface, ''), 'unknown');
BEGIN
  IF p_status IS NULL OR p_status NOT IN ('start', 'crashed')
     OR (v_release <> '' AND v_release !~ '^[0-9A-Za-z._-]{1,64}$')
     OR v_surface NOT IN ('erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown') THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'INVALID');
  END IF;
  IF public.sentinel_rate_hit('session:' || coalesce(p_rate_key, 'none'), 20)
     OR public.sentinel_rate_hit('session:global', 3000) THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'RATE_LIMITED');
  END IF;
  INSERT INTO public.sentinel_session_counts AS c (release, day, surface, sessions, crashed)
  VALUES (v_release, (now() AT TIME ZONE 'UTC')::date, v_surface,
          CASE WHEN p_status = 'start' THEN 1 ELSE 0 END, CASE WHEN p_status = 'crashed' THEN 1 ELSE 0 END)
  ON CONFLICT (release, day, surface) DO UPDATE
     SET sessions = c.sessions + EXCLUDED.sessions, crashed = c.crashed + EXCLUDED.crashed;
  RETURN jsonb_build_object('accepted', true);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_session_beat(text, text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_session_beat(text, text, text, text) TO service_role;

-- Santé par version (exploitant) : sessions, plantées, taux sans plantage
-- (NULL sans session : jamais 100 % inventés).
CREATE OR REPLACE FUNCTION public.sentinel_release_health(p_days integer DEFAULT 14)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  RETURN coalesce((
    SELECT jsonb_agg(jsonb_build_object(
             'release', nullif(r.release, ''), 'sessions', r.sessions, 'crashed', least(r.crashed, r.sessions),
             'crash_free_rate', CASE WHEN r.sessions > 0 THEN round(1 - least(r.crashed, r.sessions)::numeric / r.sessions, 4) END,
             'first_day', r.first_day, 'last_day', r.last_day) ORDER BY r.last_day DESC, r.release)
      FROM (SELECT release, sum(sessions) AS sessions, sum(crashed) AS crashed, min(day) AS first_day, max(day) AS last_day
              FROM public.sentinel_session_counts
             WHERE day >= (now() AT TIME ZONE 'UTC')::date - greatest(1, least(coalesce(p_days, 14), 90))
             GROUP BY release) r), '[]'::jsonb);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_release_health(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_release_health(integer) TO authenticated;

-- Retour utilisateur (service seul) : rattaché à l'événement dont le SDK a
-- donné l'identifiant (`context.client_event_id`), reçu dans l'heure ; un
-- seul retour par événement ; le message arrive DÉJÀ nettoyé par la réception.
CREATE OR REPLACE FUNCTION public.sentinel_feedback_submit(p_client_event_id uuid, p_message text, p_user uuid, p_rate_key text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  e public.sentinel_events%ROWTYPE;
  v_id uuid;
BEGIN
  IF p_client_event_id IS NULL OR p_message IS NULL OR length(btrim(p_message)) = 0 OR length(p_message) > 1000 THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'INVALID');
  END IF;
  IF public.sentinel_rate_hit('feedback:' || coalesce(p_rate_key, 'none'), 5) THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'RATE_LIMITED');
  END IF;
  SELECT * INTO e FROM public.sentinel_events
   WHERE received_at > now() - interval '1 hour'
     AND context->>'client_event_id' = p_client_event_id::text
   ORDER BY received_at DESC LIMIT 1;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'EVENT_NOT_FOUND');
  END IF;
  IF e.user_id IS NOT NULL AND e.user_id IS DISTINCT FROM p_user THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'EVENT_NOT_FOUND');
  END IF;
  INSERT INTO public.sentinel_feedback (issue_id, event_id, user_id, message)
  VALUES (e.issue_id, e.id, p_user, btrim(p_message))
  ON CONFLICT (event_id) DO NOTHING
  RETURNING id INTO v_id;
  IF v_id IS NULL THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'ALREADY_SENT');
  END IF;
  INSERT INTO public.sentinel_issue_activity (issue_id, actor, kind, payload)
  VALUES (e.issue_id, NULL, 'feedback', jsonb_build_object('feedback_id', v_id));
  RETURN jsonb_build_object('accepted', true);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_feedback_submit(uuid, text, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_feedback_submit(uuid, text, uuid, text) TO service_role;

-- Résumé hebdomadaire (service seul) : le lundi à l'heure dite DANS le fuseau
-- de l'hôte, la semaine écoulée, une fois par semaine. Interrupteur
-- `sentinel_settings.weekly_digest`, éteint par défaut. Il passe par le canal
-- d'alerte de l'hôte sous le type `weekly`.
CREATE OR REPLACE FUNCTION public.sentinel_weekly_digest(p_timezone text DEFAULT 'UTC', p_hour integer DEFAULT 8, p_now timestamptz DEFAULT now())
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_local timestamp := p_now AT TIME ZONE p_timezone;
  v_week date;
  v_from timestamptz;
  v_payload jsonb;
  v_ok boolean := false;
BEGIN
  IF NOT coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'weekly_digest'), false) THEN
    RETURN jsonb_build_object('skipped', 'disabled');
  END IF;
  IF extract(isodow FROM v_local) <> 1 OR extract(hour FROM v_local) <> p_hour THEN
    RETURN jsonb_build_object('skipped', 'not_due');
  END IF;
  v_week := v_local::date - 7;
  v_from := (v_week::timestamp) AT TIME ZONE p_timezone;
  IF EXISTS (SELECT 1 FROM public.sentinel_weekly_digests WHERE week_start = v_week) THEN
    RETURN jsonb_build_object('skipped', 'already_sent');
  END IF;
  v_payload := jsonb_build_object(
    'week_start', v_week,
    'new_issues', (SELECT count(*) FROM public.sentinel_issues WHERE first_seen_at >= v_from AND first_seen_at < p_now AND merged_into IS NULL),
    'regressions', (SELECT count(*) FROM public.sentinel_issue_history WHERE reason = 'regression' AND at >= v_from AND at < p_now),
    'open_issues', (SELECT count(*) FROM public.sentinel_issues WHERE status IN ('unresolved', 'in_progress') AND merged_into IS NULL),
    'events', (SELECT count(*) FROM public.sentinel_events WHERE received_at >= v_from AND received_at < p_now),
    'top', coalesce((SELECT jsonb_agg(jsonb_build_object('issue_id', t.id, 'title', t.title, 'events', t.n, 'status', t.status) ORDER BY t.n DESC)
                       FROM (SELECT i.id, i.title, i.status, count(*) AS n
                               FROM public.sentinel_events e JOIN public.sentinel_issues i ON i.id = e.issue_id
                              WHERE e.received_at >= v_from AND e.received_at < p_now
                              GROUP BY i.id, i.title, i.status ORDER BY count(*) DESC LIMIT 5) t), '[]'::jsonb),
    'releases', coalesce((SELECT jsonb_agg(jsonb_build_object('release', nullif(r.release, ''), 'sessions', r.s,
                                   'crash_free_rate', CASE WHEN r.s > 0 THEN round(1 - least(r.c, r.s)::numeric / r.s, 4) END) ORDER BY r.s DESC)
                            FROM (SELECT release, sum(sessions) AS s, sum(crashed) AS c FROM public.sentinel_session_counts
                                   WHERE day >= v_week AND day < v_local::date GROUP BY release ORDER BY sum(sessions) DESC LIMIT 5) r), '[]'::jsonb));
  BEGIN
    v_ok := coalesce(public.sentinel_host_alert('weekly', NULL, v_payload), false);
  EXCEPTION WHEN OTHERS THEN
    v_ok := false;
  END;
  INSERT INTO public.sentinel_weekly_digests (week_start, dispatched, payload) VALUES (v_week, v_ok, v_payload);
  RETURN jsonb_build_object('sent', v_ok, 'week_start', v_week);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_weekly_digest(text, integer, timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_weekly_digest(text, integer, timestamptz) TO service_role;

-- Interrupteurs des modules, version 6 : `monitors` et `weekly_digest`.
CREATE OR REPLACE FUNCTION public.sentinel_setting_set(p_key text, p_enabled boolean)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  IF p_key IS NULL OR p_key NOT IN ('monitors', 'weekly_digest') OR p_enabled IS NULL THEN
    RAISE EXCEPTION 'SENTINEL_SETTING_INVALID' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.sentinel_settings (key, enabled, updated_at, updated_by)
  VALUES (p_key, p_enabled, now(), auth.uid())
  ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now(), updated_by = auth.uid();
  RETURN p_enabled;
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_setting_set(text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_setting_set(text, boolean) TO authenticated;

-- Les interrupteurs, lus par l'exploitant.
CREATE OR REPLACE FUNCTION public.sentinel_settings_list()
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  RETURN jsonb_build_object(
    'monitors', coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'monitors'), false),
    'weekly_digest', coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'weekly_digest'), false));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_settings_list() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_settings_list() TO authenticated;
