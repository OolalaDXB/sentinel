-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel, module « moniteurs » — les tâches muettes (version 1).
--
-- Une tâche planifiée qui ne tourne plus ne lève rien : personne n'est là pour
-- voir l'erreur. Le moniteur lit la PREUVE d'un passage, jamais la tâche
-- elle-même : l'hôte la fournit par un crochet, lu à chaque contrôle :
--   public.sentinel_host_monitor_proofs()
--     RETURNS TABLE (name text, last_success_at timestamptz, last_failure_at timestamptz,
--                    last_error text, observed_every_minutes integer)
-- Une tâche jamais vue devient un moniteur ; sa planification attendue est
-- celle qu'on a OBSERVÉE (le plus grand écart), tant que l'exploitant n'en a
-- pas fixé une.
--
-- États : `unknown` (aucune preuve, ou planification inconnue), `ok`, `late`
-- (dernier succès plus vieux que planification + tolérance), `failed` (le
-- dernier passage a échoué). Le PASSAGE à `late` ou `failed` — et lui seul —
-- crée un événement `monitor_missed:<nom>` ou `monitor_failed:<nom>` par
-- `sentinel_ingest` : un même retard contrôlé dix fois reste UN problème, un
-- retard résolu qui revient est une régression.
--
-- Contrôle des contrôles : un moniteur jamais passé au rouge est « jamais
-- éprouvé ». `sentinel_monitor_drill(nom)` simule un retard sous l'empreinte
-- `monitor_drill:<nom>`, note si l'alerte est PARTIE, puis résout l'exercice
-- (l'exercice suivant est une régression, donc une alerte de plus).
--
-- Interrupteur : `sentinel_settings` (clé `monitors`), éteint par défaut.
-- Éteint, le contrôle ne lit ni n'écrit rien.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sentinel_settings (
  key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z_]{0,39}$'),
  enabled boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);

CREATE TABLE IF NOT EXISTS public.sentinel_monitors (
  name text PRIMARY KEY CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,47}$'),
  kind text NOT NULL DEFAULT 'job' CHECK (kind IN ('job')),
  enabled boolean NOT NULL DEFAULT true,
  expected_every_minutes integer CHECK (expected_every_minutes BETWEEN 1 AND 44640),
  expected_source text NOT NULL DEFAULT 'observed' CHECK (expected_source IN ('observed', 'manual')),
  tolerance_minutes integer CHECK (tolerance_minutes BETWEEN 0 AND 10080),
  last_success_at timestamptz,
  last_failure_at timestamptz,
  last_error text,
  state text NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown', 'ok', 'late', 'failed')),
  state_changed_at timestamptz,
  checked_at timestamptz,
  ever_red_at timestamptz,
  last_drill_at timestamptz,
  last_drill_dispatched boolean,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);

ALTER TABLE public.sentinel_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_monitors ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_settings, public.sentinel_monitors FROM PUBLIC, anon, authenticated;

-- La règle, pure : la même que `evaluateMonitor` du paquet.
CREATE OR REPLACE FUNCTION public.sentinel_monitor_state(
  p_expected integer, p_tolerance integer,
  p_last_success timestamptz, p_last_failure timestamptz, p_now timestamptz)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT CASE
    WHEN p_last_failure IS NOT NULL AND (p_last_success IS NULL OR p_last_failure > p_last_success) THEN 'failed'
    WHEN p_last_success IS NULL OR p_expected IS NULL THEN 'unknown'
    WHEN p_now - p_last_success > make_interval(mins => p_expected + coalesce(p_tolerance, 0)) THEN 'late'
    ELSE 'ok'
  END
$function$;

-- Tolérance par défaut : la moitié de la planification, deux heures de marge au moins.
CREATE OR REPLACE FUNCTION public.sentinel_monitor_default_tolerance(p_expected integer)
 RETURNS integer
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT CASE WHEN p_expected IS NULL THEN NULL
              ELSE least(10080, greatest(ceil(p_expected * 0.5)::integer, 120 - p_expected, 0)) END
$function$;

-- Un événement synthétique, par le chemin de tous les autres.
CREATE OR REPLACE FUNCTION public._sentinel_monitor_event(p_kind text, p_monitor public.sentinel_monitors, p_extra jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_title text;
  v_error text := left(regexp_replace(coalesce(p_monitor.last_error, ''), '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[email]', 'g'), 300);
BEGIN
  v_title := CASE p_kind
    WHEN 'monitor_failed' THEN 'Tâche ' || p_monitor.name || ' en échec' || CASE WHEN v_error <> '' THEN ' : ' || v_error ELSE '' END
    WHEN 'monitor_drill' THEN 'Exercice : retard simulé de la tâche ' || p_monitor.name
    ELSE 'Tâche ' || p_monitor.name || ' muette depuis ' || coalesce(to_char(p_monitor.last_success_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC', 'toujours')
  END;
  RETURN public.sentinel_ingest(jsonb_build_object(
    'v', 1,
    'fingerprint', p_kind || ':' || p_monitor.name,
    'occurred_at', now(),
    'release', NULL,
    'environment', 'production',
    'surface', 'unknown',
    'error', jsonb_build_object('type', 'unknown', 'name', 'Monitor', 'message', left(v_title, 1000), 'code', upper(p_kind)),
    'url', NULL,
    'claimed_tenant', NULL,
    'breadcrumbs', '[]'::jsonb,
    'context', jsonb_build_object(
      'monitor', p_monitor.name, 'kind', p_kind,
      'expected_every_minutes', p_monitor.expected_every_minutes,
      'tolerance_minutes', p_monitor.tolerance_minutes,
      'last_success_at', p_monitor.last_success_at,
      'last_failure_at', p_monitor.last_failure_at) || coalesce(p_extra, '{}'::jsonb)),
    'monitor:' || p_monitor.name, NULL);
END;
$function$;
REVOKE ALL ON FUNCTION public._sentinel_monitor_event(text, public.sentinel_monitors, jsonb) FROM PUBLIC, anon, authenticated;

-- Le contrôle, planifié par l'hôte (service seul). Rejoué, il ne change rien.
CREATE OR REPLACE FUNCTION public.sentinel_monitors_check(p_now timestamptz DEFAULT now())
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  r record;
  m public.sentinel_monitors%ROWTYPE;
  v_state text;
  v_kind text;
  v_checked integer := 0;
  v_opened integer := 0;
BEGIN
  IF NOT coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'monitors'), false) THEN
    RETURN jsonb_build_object('skipped', 'disabled');
  END IF;
  IF to_regprocedure('public.sentinel_host_monitor_proofs()') IS NULL THEN
    RETURN jsonb_build_object('skipped', 'no_host_hook');
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('sentinel_monitors_check'));

  FOR r IN EXECUTE 'SELECT name, last_success_at, last_failure_at, last_error, observed_every_minutes FROM public.sentinel_host_monitor_proofs()' LOOP
    CONTINUE WHEN r.name IS NULL OR r.name !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,47}$';
    INSERT INTO public.sentinel_monitors AS s (name, expected_every_minutes, tolerance_minutes, last_success_at, last_failure_at, last_error)
    VALUES (r.name, least(44640, greatest(1, r.observed_every_minutes)),
            public.sentinel_monitor_default_tolerance(least(44640, greatest(1, r.observed_every_minutes))),
            r.last_success_at, r.last_failure_at, left(r.last_error, 1000))
    ON CONFLICT (name) DO UPDATE
       SET last_success_at = EXCLUDED.last_success_at,
           last_failure_at = EXCLUDED.last_failure_at,
           last_error = EXCLUDED.last_error,
           expected_every_minutes = CASE WHEN s.expected_source = 'manual' THEN s.expected_every_minutes
                                         ELSE coalesce(EXCLUDED.expected_every_minutes, s.expected_every_minutes) END,
           tolerance_minutes = CASE WHEN s.expected_source = 'manual' THEN s.tolerance_minutes
                                    ELSE coalesce(EXCLUDED.tolerance_minutes, s.tolerance_minutes) END;
  END LOOP;

  FOR m IN SELECT * FROM public.sentinel_monitors WHERE enabled ORDER BY name FOR UPDATE LOOP
    v_checked := v_checked + 1;
    v_state := public.sentinel_monitor_state(m.expected_every_minutes, m.tolerance_minutes, m.last_success_at, m.last_failure_at, p_now);
    IF v_state IS DISTINCT FROM m.state THEN
      UPDATE public.sentinel_monitors
         SET state = v_state, state_changed_at = p_now,
             ever_red_at = CASE WHEN v_state IN ('late', 'failed') THEN coalesce(ever_red_at, p_now) ELSE ever_red_at END
       WHERE name = m.name
      RETURNING * INTO m;
      IF v_state IN ('late', 'failed') THEN
        v_kind := CASE v_state WHEN 'failed' THEN 'monitor_failed' ELSE 'monitor_missed' END;
        PERFORM public._sentinel_monitor_event(v_kind, m);
        v_opened := v_opened + 1;
      END IF;
    END IF;
    UPDATE public.sentinel_monitors SET checked_at = p_now WHERE name = m.name;
  END LOOP;
  RETURN jsonb_build_object('checked', v_checked, 'opened', v_opened);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_monitors_check(timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_monitors_check(timestamptz) TO service_role;

-- Liste (exploitant).
CREATE OR REPLACE FUNCTION public.sentinel_monitor_list()
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
    'enabled', coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'monitors'), false),
    'monitors', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
               'name', m.name, 'kind', m.kind, 'enabled', m.enabled,
               'expected_every_minutes', m.expected_every_minutes, 'expected_source', m.expected_source,
               'tolerance_minutes', m.tolerance_minutes,
               'last_success_at', m.last_success_at, 'last_failure_at', m.last_failure_at,
               'last_error', left(m.last_error, 300),
               'state', m.state, 'state_changed_at', m.state_changed_at, 'checked_at', m.checked_at,
               'ever_red_at', m.ever_red_at, 'last_drill_at', m.last_drill_at,
               'last_drill_dispatched', m.last_drill_dispatched,
               'proven', (m.ever_red_at IS NOT NULL OR m.last_drill_dispatched IS TRUE),
               'issue_id', (SELECT i.id FROM public.sentinel_issues i
                             WHERE i.fingerprint IN ('monitor_missed:' || m.name, 'monitor_failed:' || m.name)
                             ORDER BY i.last_seen_at DESC LIMIT 1))
             ORDER BY m.name)
        FROM public.sentinel_monitors m), '[]'::jsonb));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_monitor_list() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_monitor_list() TO authenticated;

-- Allumer ou éteindre un module (exploitant).
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
  IF p_key IS NULL OR p_key NOT IN ('monitors') OR p_enabled IS NULL THEN
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

-- Régler un moniteur (exploitant). Planification NULL = rendre la main à l'observation.
CREATE OR REPLACE FUNCTION public.sentinel_monitor_save(p_name text, p_enabled boolean, p_expected integer, p_tolerance integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  m public.sentinel_monitors%ROWTYPE;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  UPDATE public.sentinel_monitors
     SET enabled = coalesce(p_enabled, enabled),
         expected_every_minutes = CASE WHEN p_expected IS NULL THEN expected_every_minutes ELSE p_expected END,
         expected_source = CASE WHEN p_expected IS NULL THEN 'observed' ELSE 'manual' END,
         tolerance_minutes = coalesce(p_tolerance, CASE WHEN p_expected IS NULL THEN tolerance_minutes
                                                        ELSE public.sentinel_monitor_default_tolerance(p_expected) END),
         updated_at = now(), updated_by = auth.uid()
   WHERE name = p_name
  RETURNING * INTO m;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_MONITOR_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  RETURN to_jsonb(m);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_monitor_save(text, boolean, integer, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_monitor_save(text, boolean, integer, integer) TO authenticated;

-- Éprouver un moniteur : un retard SIMULÉ, l'alerte demandée pour de vrai,
-- son résultat noté, l'exercice résolu (exploitant).
CREATE OR REPLACE FUNCTION public.sentinel_monitor_drill(p_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  m public.sentinel_monitors%ROWTYPE;
  v_res jsonb;
  v_issue uuid;
  v_dispatched boolean;
  v_from text;
  v_before bigint;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO m FROM public.sentinel_monitors WHERE name = p_name FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_MONITOR_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  -- Compter AVANT : une alerte d'un exercice précédent ne prouve pas celui-ci.
  SELECT count(*) INTO v_before FROM public.sentinel_alerts a
    JOIN public.sentinel_issues i ON i.id = a.issue_id
   WHERE i.fingerprint = 'monitor_drill:' || m.name AND a.dispatched;
  v_res := public._sentinel_monitor_event('monitor_drill', m, jsonb_build_object('drill', true));
  IF NOT coalesce((v_res->>'accepted')::boolean, false) THEN
    v_dispatched := false;
  ELSE
    v_issue := (v_res->>'issue_id')::uuid;
    v_dispatched := (SELECT count(*) FROM public.sentinel_alerts a WHERE a.issue_id = v_issue AND a.dispatched) > v_before;
    SELECT status INTO v_from FROM public.sentinel_issues WHERE id = v_issue;
    IF v_from IS DISTINCT FROM 'resolved' THEN
      UPDATE public.sentinel_issues
         SET status = 'resolved', status_changed_at = now(), status_changed_by = auth.uid(),
             status_note = 'Exercice de moniteur', resolved_release = NULL
       WHERE id = v_issue;
      INSERT INTO public.sentinel_issue_history (issue_id, from_status, to_status, actor, reason, note)
      VALUES (v_issue, v_from, 'resolved', auth.uid(), 'manual', 'Exercice de moniteur');
    END IF;
  END IF;
  UPDATE public.sentinel_monitors SET last_drill_at = now(), last_drill_dispatched = v_dispatched WHERE name = p_name;
  RETURN jsonb_build_object('dispatched', v_dispatched, 'issue_id', v_issue, 'reason', v_res->>'reason');
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_monitor_drill(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_monitor_drill(text) TO authenticated;
