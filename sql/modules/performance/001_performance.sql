-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel, module « performance » (version 1) : Web Vitals et requêtes lentes.
--
-- Web Vitals (LCP, INP, CLS, TTFB), échantillonnées par le navigateur (10 %),
-- rangées par VERSION, ROUTE NORMALISÉE, surface et jour dans un HISTOGRAMME :
-- une valeur tombe dans une classe de 10 % de large (`sentinel_vitals_bin`),
-- seul le compte de la classe est gardé. Aucune mesure isolée, aucun
-- identifiant, aucune croissance par visite : un percentile se lit sur les
-- classes, à 10 % près, assez pour voir une dégradation de 20 %.
--
-- Régression : pour une route et une mesure, le p75 de la DERNIÈRE version
-- (30 mesures au moins) dépasse de plus de 20 % celui de la version d'avant
-- (30 mesures au moins). `sentinel_vitals_check` ouvre alors UN problème
-- `perf_regression:` par route et mesure (une régression déjà résolue qui
-- revient est une régression Sentinel, donc une alerte).
--
-- Requêtes lentes : AUCUN second journal. Le crochet FACULTATIF de l'hôte rend
-- son propre journal, avec l'acteur :
--   public.sentinel_host_slow_operations(p_since timestamptz)
--     RETURNS TABLE (operation text, duration_ms integer, at timestamptz, actor_key text, actor_label text)
--
-- Interrupteur : `sentinel_settings.vitals_check` (le contrôle des
-- régressions), éteint par défaut. La réception ne dépend que du navigateur.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sentinel_vitals_buckets (
  release text NOT NULL,
  route text NOT NULL CHECK (route ~ '^/[A-Za-z0-9/:_.-]{0,199}$'),
  metric text NOT NULL CHECK (metric IN ('lcp', 'inp', 'cls', 'ttfb')),
  surface text NOT NULL CHECK (surface IN ('erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown')),
  day date NOT NULL,
  bin smallint NOT NULL CHECK (bin BETWEEN 0 AND 200),
  n bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (release, route, metric, surface, day, bin)
);
CREATE INDEX IF NOT EXISTS sentinel_vitals_buckets_day_idx ON public.sentinel_vitals_buckets (day);
ALTER TABLE public.sentinel_vitals_buckets ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_vitals_buckets FROM PUBLIC, anon, authenticated;

-- La classe d'une valeur : 0 pour 0, puis classes géométriques de 10 %. Le CLS
-- (sans unité) est compté en millièmes.
CREATE OR REPLACE FUNCTION public.sentinel_vitals_bin(p_metric text, p_value double precision)
 RETURNS smallint
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT CASE
    WHEN p_value IS NULL OR p_value <= 0 THEN 0
    ELSE least(200, 1 + floor(ln(CASE WHEN p_metric = 'cls' THEN p_value * 1000 ELSE p_value END + 1) / ln(1.1)))::smallint
  END
$function$;

-- La borne haute d'une classe, dans l'unité de la mesure.
CREATE OR REPLACE FUNCTION public.sentinel_vitals_bin_upper(p_metric text, p_bin smallint)
 RETURNS double precision
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT CASE WHEN p_bin <= 0 THEN 0
              ELSE (power(1.1, p_bin) - 1) / CASE WHEN p_metric = 'cls' THEN 1000 ELSE 1 END END
$function$;

-- Réception (service seul) : les mesures d'UN chargement de page.
CREATE OR REPLACE FUNCTION public.sentinel_vitals_record(p_release text, p_route text, p_surface text, p_metrics jsonb, p_rate_key text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_release text := coalesce(nullif(btrim(p_release), ''), '');
  v_surface text := coalesce(nullif(p_surface, ''), 'unknown');
  v_day date := (now() AT TIME ZONE 'UTC')::date;
  v_key text;
  v_val double precision;
  v_n integer := 0;
BEGIN
  IF p_route IS NULL OR p_route !~ '^/[A-Za-z0-9/:_.-]{0,199}$'
     OR (v_release <> '' AND v_release !~ '^[0-9A-Za-z._-]{1,64}$')
     OR v_surface NOT IN ('erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown')
     OR jsonb_typeof(p_metrics) IS DISTINCT FROM 'object' THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'INVALID');
  END IF;
  IF public.sentinel_rate_hit('vitals:' || coalesce(p_rate_key, 'none'), 20)
     OR public.sentinel_rate_hit('vitals:global', 3000) THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'RATE_LIMITED');
  END IF;
  FOR v_key IN SELECT jsonb_object_keys(p_metrics) LOOP
    CONTINUE WHEN v_key NOT IN ('lcp', 'inp', 'cls', 'ttfb') OR jsonb_typeof(p_metrics->v_key) <> 'number';
    v_val := (p_metrics->>v_key)::double precision;
    CONTINUE WHEN v_val < 0 OR (v_key = 'cls' AND v_val > 100) OR (v_key <> 'cls' AND v_val > 120000);
    INSERT INTO public.sentinel_vitals_buckets AS b (release, route, metric, surface, day, bin, n)
    VALUES (v_release, p_route, v_key, v_surface, v_day, public.sentinel_vitals_bin(v_key, v_val), 1)
    ON CONFLICT (release, route, metric, surface, day, bin) DO UPDATE SET n = b.n + 1;
    v_n := v_n + 1;
  END LOOP;
  IF v_n = 0 THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'INVALID');
  END IF;
  RETURN jsonb_build_object('accepted', true, 'metrics', v_n);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_vitals_record(text, text, text, jsonb, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_vitals_record(text, text, text, jsonb, text) TO service_role;

-- Percentiles par version, route et mesure, sur les N derniers jours. Interne.
CREATE OR REPLACE FUNCTION public._sentinel_vitals_percentiles(p_days integer)
 RETURNS TABLE (release text, route text, metric text, n bigint, p50 double precision, p75 double precision, p95 double precision, first_day date, last_day date)
 LANGUAGE sql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  WITH agg AS (
    SELECT b.release, b.route, b.metric, b.bin, sum(b.n) AS n, min(b.day) AS first_day, max(b.day) AS last_day
      FROM public.sentinel_vitals_buckets b
     WHERE b.day >= (now() AT TIME ZONE 'UTC')::date - greatest(1, least(coalesce(p_days, 30), 90))
     GROUP BY 1, 2, 3, 4
  ), cum AS (
    SELECT a.*, sum(a.n) OVER w AS cum_n, sum(a.n) OVER (PARTITION BY a.release, a.route, a.metric) AS total,
           min(a.first_day) OVER (PARTITION BY a.release, a.route, a.metric) AS f,
           max(a.last_day) OVER (PARTITION BY a.release, a.route, a.metric) AS l
      FROM agg a
    WINDOW w AS (PARTITION BY a.release, a.route, a.metric ORDER BY a.bin)
  )
  SELECT c.release, c.route, c.metric, max(c.total)::bigint,
         public.sentinel_vitals_bin_upper(c.metric, min(c.bin) FILTER (WHERE c.cum_n >= 0.50 * c.total)::smallint),
         public.sentinel_vitals_bin_upper(c.metric, min(c.bin) FILTER (WHERE c.cum_n >= 0.75 * c.total)::smallint),
         public.sentinel_vitals_bin_upper(c.metric, min(c.bin) FILTER (WHERE c.cum_n >= 0.95 * c.total)::smallint),
         min(c.f), max(c.l)
    FROM cum c
   GROUP BY c.release, c.route, c.metric
$function$;
REVOKE ALL ON FUNCTION public._sentinel_vitals_percentiles(integer) FROM PUBLIC, anon, authenticated;

-- Pour chaque route et mesure : la dernière version et celle d'avant, et la
-- régression (p75 > +20 %, 30 mesures au moins de chaque côté). Interne.
CREATE OR REPLACE FUNCTION public._sentinel_vitals_regressions(p_days integer)
 RETURNS TABLE (route text, metric text, release text, previous_release text, p75 double precision, previous_p75 double precision, n bigint, previous_n bigint, regressed boolean)
 LANGUAGE sql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  WITH p AS (
    SELECT x.*, row_number() OVER (PARTITION BY x.route, x.metric ORDER BY x.first_day DESC, x.last_day DESC, x.release DESC) AS rk
      FROM public._sentinel_vitals_percentiles(p_days) x
  )
  SELECT cur.route, cur.metric, nullif(cur.release, ''), nullif(prev.release, ''), cur.p75, prev.p75, cur.n, prev.n,
         coalesce(cur.n >= 30 AND prev.n >= 30 AND prev.p75 > 0 AND cur.p75 > prev.p75 * 1.2, false)
    FROM p cur
    LEFT JOIN p prev ON prev.route = cur.route AND prev.metric = cur.metric AND prev.rk = 2
   WHERE cur.rk = 1
$function$;
REVOKE ALL ON FUNCTION public._sentinel_vitals_regressions(integer) FROM PUBLIC, anon, authenticated;

-- Lecture (exploitant) : percentiles par version, et les régressions.
CREATE OR REPLACE FUNCTION public.sentinel_vitals_summary(p_days integer DEFAULT 30)
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
    'rows', coalesce((SELECT jsonb_agg(jsonb_build_object(
               'release', nullif(x.release, ''), 'route', x.route, 'metric', x.metric, 'n', x.n,
               'p50', x.p50, 'p75', x.p75, 'p95', x.p95, 'first_day', x.first_day, 'last_day', x.last_day)
             ORDER BY x.route, x.metric, x.last_day DESC) FROM public._sentinel_vitals_percentiles(p_days) x), '[]'::jsonb),
    'regressions', coalesce((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.route, r.metric)
                               FROM public._sentinel_vitals_regressions(p_days) r WHERE r.regressed), '[]'::jsonb));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_vitals_summary(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_vitals_summary(integer) TO authenticated;

-- Contrôle des régressions (service seul, planifié par l'hôte) : UN problème
-- par route et mesure qui régresse ; rejoué, il ne recompte pas une version
-- déjà signalée.
CREATE OR REPLACE FUNCTION public.sentinel_vitals_check(p_days integer DEFAULT 30)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  r record;
  v_fp text;
  v_opened integer := 0;
  v_label text;
BEGIN
  IF NOT coalesce((SELECT enabled FROM public.sentinel_settings WHERE key = 'vitals_check'), false) THEN
    RETURN jsonb_build_object('skipped', 'disabled');
  END IF;
  FOR r IN SELECT * FROM public._sentinel_vitals_regressions(p_days) WHERE regressed LOOP
    v_fp := 'perf_regression:' || left(md5(r.metric || '|' || r.route), 24);
    -- Une même version ne se signale qu'une fois pour une route et une mesure.
    CONTINUE WHEN EXISTS (SELECT 1 FROM public.sentinel_events e JOIN public.sentinel_issues i ON i.id = e.issue_id
                           WHERE i.fingerprint = v_fp AND e.release IS NOT DISTINCT FROM r.release);
    v_label := upper(r.metric) || ' p75 +' || round((r.p75 / r.previous_p75 - 1) * 100)::text || ' % sur ' || r.route;
    PERFORM public.sentinel_ingest(jsonb_build_object(
      'v', 1, 'fingerprint', v_fp, 'occurred_at', now(), 'release', r.release, 'environment', 'production',
      'surface', 'unknown',
      'error', jsonb_build_object('type', 'unknown', 'name', 'PerformanceRegression', 'message', left(v_label, 1000), 'code', 'PERF_REGRESSION'),
      'url', r.route, 'claimed_tenant', NULL, 'breadcrumbs', '[]'::jsonb,
      'context', jsonb_build_object('metric', r.metric, 'route', r.route, 'p75', round(r.p75::numeric, 3),
                                    'previous_p75', round(r.previous_p75::numeric, 3), 'previous_release', r.previous_release,
                                    'samples', r.n, 'previous_samples', r.previous_n)),
      'perf:' || r.metric, NULL);
    v_opened := v_opened + 1;
  END LOOP;
  RETURN jsonb_build_object('opened', v_opened);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_vitals_check(integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_vitals_check(integer) TO service_role;

-- Requêtes lentes (exploitant) : le journal de l'HÔTE, regroupé par opération,
-- avec ses acteurs — jamais copié ailleurs.
CREATE OR REPLACE FUNCTION public.sentinel_slow_operations(p_days integer DEFAULT 7, p_limit integer DEFAULT 50)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_since timestamptz := now() - make_interval(days => greatest(1, least(coalesce(p_days, 7), 90)));
  v_out jsonb;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  IF to_regprocedure('public.sentinel_host_slow_operations(timestamp with time zone)') IS NULL THEN
    RETURN jsonb_build_object('available', false, 'operations', '[]'::jsonb);
  END IF;
  EXECUTE $q$
    WITH s AS (SELECT * FROM public.sentinel_host_slow_operations($1)),
    ops AS (
      SELECT s.operation, count(*) AS n,
             percentile_disc(0.5) WITHIN GROUP (ORDER BY s.duration_ms) AS p50,
             percentile_disc(0.95) WITHIN GROUP (ORDER BY s.duration_ms) AS p95,
             max(s.duration_ms) AS max_ms, max(s.at) AS last_at,
             count(DISTINCT s.actor_key) AS actors
        FROM s GROUP BY s.operation ORDER BY count(*) DESC, max(s.duration_ms) DESC LIMIT $2)
    SELECT coalesce(jsonb_agg(jsonb_build_object(
             'operation', o.operation, 'count', o.n, 'p50_ms', o.p50, 'p95_ms', o.p95, 'max_ms', o.max_ms,
             'last_at', o.last_at, 'actors', o.actors,
             'top_actors', (SELECT coalesce(jsonb_agg(jsonb_build_object('label', t.actor_label, 'count', t.n) ORDER BY t.n DESC), '[]'::jsonb)
                              FROM (SELECT s.actor_label, count(*) AS n FROM s
                                     WHERE s.operation = o.operation AND s.actor_key IS NOT NULL
                                     GROUP BY s.actor_label ORDER BY count(*) DESC LIMIT 3) t))
           ORDER BY o.n DESC, o.max_ms DESC), '[]'::jsonb)
      FROM ops o
  $q$ INTO v_out USING v_since, greatest(1, least(coalesce(p_limit, 50), 200));
  RETURN jsonb_build_object('available', true, 'operations', v_out);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_slow_operations(integer, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_slow_operations(integer, integer) TO authenticated;
