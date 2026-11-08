-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel, module « uptime » (version 1) : moniteurs HTTP.
--
-- La PREUVE se lit sur la RÉPONSE, jamais sur l'envoi : un client HTTP de base
-- est souvent asynchrone (une requête partie n'a rien prouvé). Deux crochets
-- de l'hôte, FACULTATIFS (absents : le module ne fait rien) :
--   public.sentinel_host_http_request(p_url text, p_timeout_ms integer) RETURNS bigint
--     part une requête GET et rend sa référence (sans attendre la réponse) ;
--   public.sentinel_host_http_responses(p_refs bigint[])
--     RETURNS TABLE (ref bigint, status_code integer, error text, timed_out boolean, responded_at timestamptz)
--     les réponses arrivées pour ces références.
-- Sans réponse dans l'heure : un ÉCHEC, pas un « inconnu ».
--
-- Un moniteur passe « down » à N échecs D'AFFILÉE (N réglable, 3 par défaut) :
-- UN problème `uptime_down:<nom>` par `sentinel_ingest`, donc une alerte
-- « nouveau problème » ou « régression ». Rétabli, il repasse « up » et son
-- problème est RÉSOLU : la panne suivante est une régression, donc une alerte.
--
-- Interrupteur : `sentinel_settings.http_monitors`, éteint par défaut.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sentinel_http_monitors (
  name text PRIMARY KEY CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,47}$'),
  url text NOT NULL CHECK (url ~ '^https://[^\s/@]+(/[^\s]*)?$' AND length(url) <= 500),
  expected_status integer[] CHECK (expected_status IS NULL OR (cardinality(expected_status) BETWEEN 1 AND 10)),
  interval_minutes integer NOT NULL DEFAULT 5 CHECK (interval_minutes BETWEEN 1 AND 1440),
  timeout_ms integer NOT NULL DEFAULT 10000 CHECK (timeout_ms BETWEEN 1000 AND 30000),
  failure_threshold integer NOT NULL DEFAULT 3 CHECK (failure_threshold BETWEEN 1 AND 10),
  enabled boolean NOT NULL DEFAULT true,
  state text NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown', 'up', 'down')),
  state_changed_at timestamptz,
  ever_down_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);

CREATE TABLE IF NOT EXISTS public.sentinel_http_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  monitor text NOT NULL REFERENCES public.sentinel_http_monitors(name),
  requested_at timestamptz NOT NULL DEFAULT now(),
  request_ref bigint,
  status_code integer,
  healthy boolean,
  error text,
  responded_at timestamptz,
  response_ms integer
);
CREATE INDEX IF NOT EXISTS sentinel_http_checks_monitor_idx ON public.sentinel_http_checks (monitor, requested_at DESC);
CREATE INDEX IF NOT EXISTS sentinel_http_checks_pending_idx ON public.sentinel_http_checks (request_ref) WHERE healthy IS NULL;

ALTER TABLE public.sentinel_http_monitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_http_checks ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_http_monitors, public.sentinel_http_checks FROM PUBLIC, anon, authenticated;

-- La règle, pure (la même que `isHealthyStatus` du paquet) : un statut attendu
-- s'il y en a, sinon 2xx ou 3xx. Un délai dépassé ou une absence n'est jamais sain.
CREATE OR REPLACE FUNCTION public.sentinel_http_healthy(p_status integer, p_expected integer[], p_timed_out boolean)
 RETURNS boolean
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT CASE
    WHEN coalesce(p_timed_out, false) OR p_status IS NULL OR p_status <= 0 THEN false
    WHEN p_expected IS NOT NULL THEN p_status = ANY (p_expected)
    ELSE p_status BETWEEN 200 AND 399
  END
$function$;

-- Le tour (service seul, planifié par l'hôte) : relever, évaluer, sonder.
CREATE OR REPLACE FUNCTION public.sentinel_http_monitors_tick(p_now timestamptz DEFAULT now())
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  r record;
  m public.sentinel_http_monitors%ROWTYPE;
  v_refs bigint[];
  v_ref bigint;
  v_fails integer;
  v_last boolean;
  v_state text;
  v_issue uuid;
  v_sent integer := 0;
  v_opened integer := 0;
  v_closed integer := 0;
BEGIN
  IF NOT coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'http_monitors'), false) THEN
    RETURN jsonb_build_object('skipped', 'disabled');
  END IF;
  IF to_regprocedure('public.sentinel_host_http_request(text,integer)') IS NULL
     OR to_regprocedure('public.sentinel_host_http_responses(bigint[])') IS NULL THEN
    RETURN jsonb_build_object('skipped', 'no_host_hook');
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('sentinel_http_monitors_tick'));

  -- 1. Relever les réponses arrivées.
  SELECT array_agg(request_ref) INTO v_refs FROM public.sentinel_http_checks WHERE healthy IS NULL AND request_ref IS NOT NULL;
  IF v_refs IS NOT NULL THEN
    FOR r IN EXECUTE 'SELECT ref, status_code, error, timed_out, responded_at FROM public.sentinel_host_http_responses($1)' USING v_refs LOOP
      UPDATE public.sentinel_http_checks c
         SET status_code = coalesce(r.status_code, 0),
             healthy = public.sentinel_http_healthy(r.status_code, mon.expected_status, r.timed_out),
             error = CASE WHEN coalesce(r.timed_out, false) THEN 'TIMEOUT' ELSE left(nullif(r.error, ''), 300) END,
             responded_at = coalesce(r.responded_at, p_now),
             response_ms = greatest(0, (extract(epoch FROM (coalesce(r.responded_at, p_now) - c.requested_at)) * 1000)::integer)
        FROM public.sentinel_http_monitors mon
       WHERE c.request_ref = r.ref AND c.healthy IS NULL AND mon.name = c.monitor;
    END LOOP;
  END IF;

  -- 2. Sans réponse dans l'heure : un échec.
  UPDATE public.sentinel_http_checks
     SET healthy = false, status_code = 0, error = 'NO_RESPONSE'
   WHERE healthy IS NULL AND requested_at < p_now - interval '1 hour';

  -- 3. Évaluer : échecs D'AFFILÉE depuis le dernier succès.
  FOR m IN SELECT * FROM public.sentinel_http_monitors ORDER BY name FOR UPDATE LOOP
    SELECT healthy INTO v_last FROM public.sentinel_http_checks
     WHERE monitor = m.name AND healthy IS NOT NULL ORDER BY requested_at DESC, id DESC LIMIT 1;
    SELECT count(*) INTO v_fails FROM public.sentinel_http_checks c
     WHERE c.monitor = m.name AND c.healthy = false
       AND c.requested_at > coalesce((SELECT max(s.requested_at) FROM public.sentinel_http_checks s
                                       WHERE s.monitor = m.name AND s.healthy), '-infinity'::timestamptz);
    v_state := CASE WHEN v_last IS NULL THEN m.state
                    WHEN v_last THEN 'up'
                    WHEN v_fails >= m.failure_threshold THEN 'down'
                    ELSE m.state END;
    IF v_state IS DISTINCT FROM m.state THEN
      UPDATE public.sentinel_http_monitors
         SET state = v_state, state_changed_at = p_now,
             ever_down_at = CASE WHEN v_state = 'down' THEN coalesce(ever_down_at, p_now) ELSE ever_down_at END
       WHERE name = m.name;
      IF v_state = 'down' THEN
        PERFORM public.sentinel_ingest(jsonb_build_object(
          'v', 1, 'fingerprint', 'uptime_down:' || m.name, 'occurred_at', p_now, 'release', NULL,
          'environment', 'production', 'surface', 'unknown',
          'error', jsonb_build_object('type', 'network', 'name', 'UptimeDown',
                     'message', 'Service ' || m.name || ' injoignable : ' || v_fails || ' échec(s) d''affilée', 'code', 'UPTIME_DOWN'),
          'url', NULL, 'claimed_tenant', NULL, 'breadcrumbs', '[]'::jsonb,
          'context', jsonb_build_object('monitor', m.name, 'failures', v_fails, 'threshold', m.failure_threshold,
                       'last_status', (SELECT status_code FROM public.sentinel_http_checks WHERE monitor = m.name AND healthy IS NOT NULL ORDER BY requested_at DESC LIMIT 1),
                       'last_error', (SELECT error FROM public.sentinel_http_checks WHERE monitor = m.name AND healthy IS NOT NULL ORDER BY requested_at DESC LIMIT 1))),
          'uptime:' || m.name, NULL);
        v_opened := v_opened + 1;
      ELSIF v_state = 'up' AND m.state = 'down' THEN
        -- Rétabli : le problème est résolu, la panne suivante sera une régression.
        SELECT id INTO v_issue FROM public.sentinel_issues
         WHERE fingerprint = 'uptime_down:' || m.name AND status IN ('unresolved', 'in_progress');
        IF v_issue IS NOT NULL THEN
          INSERT INTO public.sentinel_issue_history (issue_id, from_status, to_status, actor, reason, note)
          SELECT v_issue, status, 'resolved', NULL, 'manual', 'Rétabli : sonde au vert' FROM public.sentinel_issues WHERE id = v_issue;
          UPDATE public.sentinel_issues
             SET status = 'resolved', status_changed_at = p_now, status_changed_by = NULL, status_note = 'Rétabli : sonde au vert'
           WHERE id = v_issue;
          v_closed := v_closed + 1;
        END IF;
      END IF;
    END IF;
  END LOOP;

  -- 4. Sonder ce qui est dû (un moniteur à la fois : une panne d'envoi n'arrête pas les autres).
  FOR m IN SELECT * FROM public.sentinel_http_monitors mm
            WHERE mm.enabled
              AND NOT EXISTS (SELECT 1 FROM public.sentinel_http_checks c WHERE c.monitor = mm.name AND c.healthy IS NULL)
              AND coalesce((SELECT max(c.requested_at) FROM public.sentinel_http_checks c WHERE c.monitor = mm.name), '-infinity'::timestamptz)
                  <= p_now - make_interval(mins => mm.interval_minutes) + interval '30 seconds'
            ORDER BY mm.name LOOP
    BEGIN
      EXECUTE 'SELECT public.sentinel_host_http_request($1, $2)' INTO v_ref USING m.url, m.timeout_ms;
      INSERT INTO public.sentinel_http_checks (monitor, requested_at, request_ref) VALUES (m.name, p_now, v_ref);
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO public.sentinel_http_checks (monitor, requested_at, request_ref, status_code, healthy, error)
      VALUES (m.name, p_now, NULL, 0, false, left('REQUEST_FAILED: ' || SQLERRM, 300));
    END;
    v_sent := v_sent + 1;
  END LOOP;
  RETURN jsonb_build_object('sent', v_sent, 'opened', v_opened, 'closed', v_closed);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_http_monitors_tick(timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_http_monitors_tick(timestamptz) TO service_role;

-- Liste (exploitant) : état, dernières vérifications, disponibilité 24 h.
CREATE OR REPLACE FUNCTION public.sentinel_http_monitor_list()
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
    'enabled', coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'http_monitors'), false),
    'monitors', coalesce((SELECT jsonb_agg(jsonb_build_object(
        'name', m.name, 'url', m.url, 'expected_status', m.expected_status, 'interval_minutes', m.interval_minutes,
        'timeout_ms', m.timeout_ms, 'failure_threshold', m.failure_threshold, 'enabled', m.enabled,
        'state', m.state, 'state_changed_at', m.state_changed_at, 'ever_down_at', m.ever_down_at,
        'checks_24h', (SELECT count(*) FROM public.sentinel_http_checks c WHERE c.monitor = m.name AND c.healthy IS NOT NULL AND c.requested_at > now() - interval '24 hours'),
        'healthy_24h', (SELECT count(*) FROM public.sentinel_http_checks c WHERE c.monitor = m.name AND c.healthy AND c.requested_at > now() - interval '24 hours'),
        'last', (SELECT jsonb_build_object('at', c.requested_at, 'status_code', c.status_code, 'healthy', c.healthy, 'error', c.error, 'response_ms', c.response_ms)
                   FROM public.sentinel_http_checks c WHERE c.monitor = m.name AND c.healthy IS NOT NULL ORDER BY c.requested_at DESC LIMIT 1),
        'issue_id', (SELECT i.id FROM public.sentinel_issues i WHERE i.fingerprint = 'uptime_down:' || m.name))
      ORDER BY m.name) FROM public.sentinel_http_monitors m), '[]'::jsonb));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_http_monitor_list() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_http_monitor_list() TO authenticated;

-- Créer ou régler un moniteur (exploitant). https seulement, sans secret dans l'adresse.
CREATE OR REPLACE FUNCTION public.sentinel_http_monitor_save(
  p_name text, p_url text, p_expected integer[] DEFAULT NULL, p_interval integer DEFAULT 5,
  p_timeout integer DEFAULT 10000, p_threshold integer DEFAULT 3, p_enabled boolean DEFAULT true)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  m public.sentinel_http_monitors%ROWTYPE;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  -- La forme (https, pas d'identifiant avant l'hôte) est tenue par la table ;
  -- ici, ce qu'elle ne voit pas : un secret dans la requête.
  IF p_url IS NULL OR p_url ~* '[?&](token|key|apikey|secret|password)=' THEN
    RAISE EXCEPTION 'SENTINEL_HTTP_URL_INVALID' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.sentinel_http_monitors AS x (name, url, expected_status, interval_minutes, timeout_ms, failure_threshold, enabled, updated_at, updated_by)
  VALUES (p_name, p_url, p_expected, coalesce(p_interval, 5), coalesce(p_timeout, 10000), coalesce(p_threshold, 3), coalesce(p_enabled, true), now(), auth.uid())
  ON CONFLICT (name) DO UPDATE
     SET url = EXCLUDED.url, expected_status = EXCLUDED.expected_status, interval_minutes = EXCLUDED.interval_minutes,
         timeout_ms = EXCLUDED.timeout_ms, failure_threshold = EXCLUDED.failure_threshold, enabled = EXCLUDED.enabled,
         updated_at = now(), updated_by = auth.uid()
  RETURNING * INTO m;
  RETURN to_jsonb(m);
EXCEPTION WHEN check_violation THEN
  RAISE EXCEPTION 'SENTINEL_HTTP_MONITOR_INVALID' USING ERRCODE = '22023';
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_http_monitor_save(text, text, integer[], integer, integer, integer, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_http_monitor_save(text, text, integer[], integer, integer, integer, boolean) TO authenticated;
