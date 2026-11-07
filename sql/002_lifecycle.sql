-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — cycle de vie, régressions, règles d'alerte, purge (version 2).
--
-- Installé APRÈS 001_sentinel.sql et APRÈS que l'hôte a défini, en plus de
-- `sentinel_host_tenant` :
--   public.sentinel_host_is_operator() RETURNS boolean
--     vrai si l'appelant courant peut trier les erreurs (strictement vrai ou
--     faux, jamais NULL) ;
--   public.sentinel_host_alert(p_kind text, p_issue uuid, p_payload jsonb) RETURNS boolean
--     demande l'envoi d'une alerte à l'exploitant ; vrai si la demande est
--     partie. Ne lève jamais : une alerte ratée ne fait pas perdre l'événement.
--
-- Cycle de vie : non résolu → en cours → résolu / ignoré. Un problème RÉSOLU
-- qui revient est une RÉGRESSION : il redevient non résolu, le compteur de
-- régressions monte, l'historique le dit. Un problème IGNORÉ compte ses
-- événements mais n'alerte jamais. Ignorer exige un motif.
--
-- Alertes : trois règles (nouveau problème, régression, fréquence), chacune
-- activable ; un plafond de 10 alertes par heure, toutes règles confondues ;
-- chaque demande est inscrite avec son résultat (`sentinel_alerts`).
--
-- Purge : `sentinel_purge(jours)` retire les ÉVÉNEMENTS plus vieux que N
-- jours (30 au moins) et les compteurs de débit périmés ; les problèmes, leurs
-- compteurs et leur historique restent. C'est la seule fonction du module qui
-- supprime.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS status_changed_at timestamptz;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS status_changed_by uuid;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS status_note text;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS resolved_release text;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS regression_count integer NOT NULL DEFAULT 0;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS last_regressed_at timestamptz;
CREATE INDEX IF NOT EXISTS sentinel_issues_status_idx ON public.sentinel_issues (status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS public.sentinel_issue_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  at timestamptz NOT NULL DEFAULT now(),
  from_status text NOT NULL,
  to_status text NOT NULL,
  actor uuid,
  reason text NOT NULL CHECK (reason IN ('manual', 'regression')),
  note text,
  release text
);
CREATE INDEX IF NOT EXISTS sentinel_issue_history_issue_idx ON public.sentinel_issue_history (issue_id, at DESC);

CREATE TABLE IF NOT EXISTS public.sentinel_alert_rules (
  kind text PRIMARY KEY CHECK (kind IN ('new_issue', 'regression', 'frequency')),
  enabled boolean NOT NULL,
  threshold integer NOT NULL DEFAULT 20 CHECK (threshold BETWEEN 2 AND 10000),
  window_minutes integer NOT NULL DEFAULT 60 CHECK (window_minutes BETWEEN 5 AND 1440),
  cooldown_minutes integer NOT NULL DEFAULT 360 CHECK (cooldown_minutes BETWEEN 15 AND 10080),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
INSERT INTO public.sentinel_alert_rules (kind, enabled) VALUES
  ('new_issue', true), ('regression', true), ('frequency', true)
ON CONFLICT (kind) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.sentinel_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  kind text NOT NULL CHECK (kind IN ('new_issue', 'regression', 'frequency')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  dispatched boolean NOT NULL,
  error text
);
CREATE INDEX IF NOT EXISTS sentinel_alerts_requested_idx ON public.sentinel_alerts (requested_at DESC);
CREATE INDEX IF NOT EXISTS sentinel_alerts_issue_idx ON public.sentinel_alerts (issue_id, kind, requested_at DESC);

ALTER TABLE public.sentinel_issue_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_alerts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_issue_history, public.sentinel_alert_rules, public.sentinel_alerts FROM PUBLIC, anon, authenticated;

-- Une alerte selon les règles. Jamais pour un problème ignoré ; plafond de
-- 10 par heure ; la demande et son résultat sont inscrits.
CREATE OR REPLACE FUNCTION public._sentinel_alert(p_kind text, p_issue uuid, p_payload jsonb)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_rule public.sentinel_alert_rules%ROWTYPE;
  v_ok boolean := false;
  v_err text;
BEGIN
  SELECT * INTO v_rule FROM public.sentinel_alert_rules WHERE kind = p_kind;
  IF NOT FOUND OR NOT v_rule.enabled THEN
    RETURN false;
  END IF;
  IF EXISTS (SELECT 1 FROM public.sentinel_issues WHERE id = p_issue AND status = 'ignored') THEN
    RETURN false;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('sentinel_alert'));
  IF (SELECT count(*) FROM public.sentinel_alerts WHERE requested_at > now() - interval '1 hour') >= 10 THEN
    RETURN false;
  END IF;
  IF p_kind = 'frequency' AND EXISTS (
    SELECT 1 FROM public.sentinel_alerts
     WHERE issue_id = p_issue AND kind = 'frequency'
       AND requested_at > now() - make_interval(mins => v_rule.cooldown_minutes)) THEN
    RETURN false;
  END IF;
  BEGIN
    v_ok := coalesce(public.sentinel_host_alert(p_kind, p_issue, p_payload), false);
  EXCEPTION WHEN OTHERS THEN
    v_ok := false;
    v_err := left(SQLERRM, 300);
  END;
  INSERT INTO public.sentinel_alerts (issue_id, kind, dispatched, error)
  VALUES (p_issue, p_kind, v_ok, CASE WHEN v_ok THEN NULL ELSE coalesce(v_err, 'NOT_DISPATCHED') END);
  RETURN v_ok;
END;
$function$;
REVOKE ALL ON FUNCTION public._sentinel_alert(text, uuid, jsonb) FROM PUBLIC, anon, authenticated;

-- Réception, version 2 : la 1 plus le cycle de vie et les alertes.
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
  IF v_new THEN
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
    'new_issue', v_new, 'regression', v_regressed, 'tenant_id', v_tenant);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_ingest(jsonb, text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_ingest(jsonb, text, uuid) TO service_role;

-- Trier un problème. Réservé à l'exploitant (crochet de l'hôte) ; ignorer
-- exige un motif ; rien ne change si le statut est déjà celui demandé.
CREATE OR REPLACE FUNCTION public.sentinel_set_issue_status(p_issue uuid, p_status text, p_note text DEFAULT NULL)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_issue public.sentinel_issues%ROWTYPE;
  v_note text := nullif(btrim(coalesce(p_note, '')), '');
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  IF p_status IS NULL OR p_status NOT IN ('unresolved', 'in_progress', 'resolved', 'ignored') THEN
    RAISE EXCEPTION 'SENTINEL_STATUS_INVALID' USING ERRCODE = '22023';
  END IF;
  IF p_status = 'ignored' AND v_note IS NULL THEN
    RAISE EXCEPTION 'SENTINEL_IGNORE_NEEDS_NOTE' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_issue FROM public.sentinel_issues WHERE id = p_issue FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_ISSUE_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_issue.status = p_status THEN
    RETURN jsonb_build_object('changed', false, 'status', p_status);
  END IF;
  INSERT INTO public.sentinel_issue_history (issue_id, from_status, to_status, actor, reason, note, release)
  VALUES (v_issue.id, v_issue.status, p_status, auth.uid(), 'manual', left(v_note, 500), v_issue.last_release);
  UPDATE public.sentinel_issues
     SET status = p_status,
         status_changed_at = now(),
         status_changed_by = auth.uid(),
         status_note = left(v_note, 500),
         resolved_release = CASE WHEN p_status = 'resolved' THEN last_release ELSE resolved_release END
   WHERE id = v_issue.id;
  RETURN jsonb_build_object('changed', true, 'status', p_status);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_set_issue_status(uuid, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_set_issue_status(uuid, text, text) TO authenticated;

-- La liste des problèmes, la plus récente d'abord. Exploitant seul.
CREATE OR REPLACE FUNCTION public.sentinel_issue_list(p_status text DEFAULT NULL, p_limit integer DEFAULT 200)
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
    SELECT jsonb_agg(row_to_json(x) ORDER BY x.last_seen_at DESC)
      FROM (
        SELECT i.id, i.fingerprint, i.error_type, i.title, i.code, i.status, i.first_seen_at, i.last_seen_at,
               i.event_count, i.first_release, i.last_release, i.surfaces, i.status_changed_at, i.status_note,
               i.resolved_release, i.regression_count, i.last_regressed_at,
               (SELECT count(DISTINCT e.user_id) FROM public.sentinel_events e WHERE e.issue_id = i.id) AS users_affected,
               (SELECT count(DISTINCT e.tenant_id) FROM public.sentinel_events e WHERE e.issue_id = i.id) AS tenants_affected,
               (SELECT count(*) FROM public.sentinel_events e WHERE e.issue_id = i.id AND e.received_at > now() - interval '24 hours') AS events_24h
          FROM public.sentinel_issues i
         WHERE p_status IS NULL OR i.status = p_status
         ORDER BY i.last_seen_at DESC
         LIMIT greatest(1, least(coalesce(p_limit, 200), 500))
      ) x), '[]'::jsonb);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_list(text, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_list(text, integer) TO authenticated;

-- Le détail d'un problème : ses 20 derniers événements, son historique, ses
-- alertes, et ses événements par version. Exploitant seul.
CREATE OR REPLACE FUNCTION public.sentinel_issue_detail(p_issue uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_issue jsonb;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT to_jsonb(i) INTO v_issue FROM public.sentinel_issues i WHERE i.id = p_issue;
  IF v_issue IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'issue', v_issue,
    'events', coalesce((SELECT jsonb_agg(to_jsonb(e) - 'issue_id' ORDER BY e.received_at DESC)
                          FROM (SELECT * FROM public.sentinel_events WHERE issue_id = p_issue
                                 ORDER BY received_at DESC LIMIT 20) e), '[]'::jsonb),
    'history', coalesce((SELECT jsonb_agg(to_jsonb(h) - 'issue_id' ORDER BY h.at DESC)
                           FROM public.sentinel_issue_history h WHERE h.issue_id = p_issue), '[]'::jsonb),
    'alerts', coalesce((SELECT jsonb_agg(to_jsonb(a) - 'issue_id' ORDER BY a.requested_at DESC)
                          FROM (SELECT * FROM public.sentinel_alerts WHERE issue_id = p_issue
                                 ORDER BY requested_at DESC LIMIT 20) a), '[]'::jsonb),
    'releases', coalesce((SELECT jsonb_agg(jsonb_build_object('release', r.release, 'events', r.n, 'last_seen_at', r.last) ORDER BY r.last DESC)
                            FROM (SELECT coalesce(release, '') AS release, count(*) AS n, max(received_at) AS last
                                    FROM public.sentinel_events WHERE issue_id = p_issue GROUP BY 1) r), '[]'::jsonb));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_issue_detail(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_issue_detail(uuid) TO authenticated;

-- Les règles d'alerte, lues et réglées par l'exploitant.
CREATE OR REPLACE FUNCTION public.sentinel_alert_rules_list()
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
  RETURN coalesce((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.kind) FROM public.sentinel_alert_rules r), '[]'::jsonb);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_alert_rules_list() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_alert_rules_list() TO authenticated;

CREATE OR REPLACE FUNCTION public.sentinel_alert_rule_save(
  p_kind text, p_enabled boolean, p_threshold integer DEFAULT NULL,
  p_window_minutes integer DEFAULT NULL, p_cooldown_minutes integer DEFAULT NULL)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_rule public.sentinel_alert_rules%ROWTYPE;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  UPDATE public.sentinel_alert_rules
     SET enabled = coalesce(p_enabled, enabled),
         threshold = coalesce(p_threshold, threshold),
         window_minutes = coalesce(p_window_minutes, window_minutes),
         cooldown_minutes = coalesce(p_cooldown_minutes, cooldown_minutes),
         updated_at = now(),
         updated_by = auth.uid()
   WHERE kind = p_kind
  RETURNING * INTO v_rule;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_RULE_UNKNOWN' USING ERRCODE = '22023';
  END IF;
  RETURN to_jsonb(v_rule);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_alert_rule_save(text, boolean, integer, integer, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_alert_rule_save(text, boolean, integer, integer, integer) TO authenticated;

-- Purge planifiée : événements plus vieux que N jours (30 au moins), débit
-- périmé. Service seul. Problèmes et historique restent.
CREATE OR REPLACE FUNCTION public.sentinel_purge(p_days integer DEFAULT 90)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_days integer := greatest(30, coalesce(p_days, 90));
  v_events integer;
  v_rates integer;
BEGIN
  WITH gone AS (
    DELETE FROM public.sentinel_events WHERE received_at < now() - make_interval(days => v_days) RETURNING 1)
  SELECT count(*) INTO v_events FROM gone;
  WITH gone AS (
    DELETE FROM public.sentinel_rate_limits WHERE window_start < now() - interval '1 hour' RETURNING 1)
  SELECT count(*) INTO v_rates FROM gone;
  RETURN jsonb_build_object('days', v_days, 'events', v_events, 'rate_limits', v_rates);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_purge(integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_purge(integer) TO service_role;
