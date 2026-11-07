-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — versions et source maps (version 3, lot 4b).
--
-- Une version (le commit déployé) s'inscrit quand ses source maps sont
-- déposées, par le service seul : `sentinel_release_register`. Les maps
-- vivent dans le stockage de l'hôte, jamais servies au public ; la base ne
-- garde que le fait qu'elles existent, leur nombre et leur poids.
--
-- `sentinel_release_list` (exploitant) dit, par version : quand elle a été
-- vue, ses événements, les problèmes qu'elle a fait NAÎTRE, les régressions
-- qu'elle a ramenées, et si ses piles sont lisibles.
-- `sentinel_event_stack` (exploitant) rend la pile et la version d'un
-- événement, pour la lire avec les maps de CETTE version.
--
-- Aucun mot de suppression dans ce fichier.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sentinel_releases (
  release text PRIMARY KEY CHECK (release ~ '^[0-9a-f]{7,40}$'),
  registered_at timestamptz NOT NULL DEFAULT now(),
  map_files integer NOT NULL CHECK (map_files BETWEEN 0 AND 500),
  map_bytes bigint NOT NULL CHECK (map_bytes >= 0)
);
ALTER TABLE public.sentinel_releases ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_releases FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.sentinel_release_register(p_release text, p_files integer, p_bytes bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  IF p_release IS NULL OR p_release !~ '^[0-9a-f]{7,40}$' THEN
    RAISE EXCEPTION 'SENTINEL_RELEASE_INVALID' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.sentinel_releases (release, map_files, map_bytes)
  VALUES (p_release, coalesce(p_files, 0), coalesce(p_bytes, 0))
  ON CONFLICT (release) DO UPDATE
     SET map_files = EXCLUDED.map_files, map_bytes = EXCLUDED.map_bytes, registered_at = now();
  RETURN jsonb_build_object('release', p_release, 'map_files', p_files);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_release_register(text, integer, bigint) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_release_register(text, integer, bigint) TO service_role;

CREATE OR REPLACE FUNCTION public.sentinel_release_list(p_limit integer DEFAULT 30)
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
    SELECT jsonb_agg(row_to_json(x) ORDER BY x.last_seen_at DESC NULLS LAST)
      FROM (
        SELECT v.release,
               r.registered_at,
               coalesce(r.map_files, 0) AS map_files,
               (r.release IS NOT NULL AND r.map_files > 0) AS has_maps,
               (SELECT min(e.received_at) FROM public.sentinel_events e WHERE e.release = v.release) AS first_seen_at,
               (SELECT max(e.received_at) FROM public.sentinel_events e WHERE e.release = v.release) AS last_seen_at,
               (SELECT count(*) FROM public.sentinel_events e WHERE e.release = v.release) AS events,
               (SELECT count(*) FROM public.sentinel_issues i WHERE i.first_release = v.release) AS new_issues,
               (SELECT count(*) FROM public.sentinel_issue_history h WHERE h.reason = 'regression' AND h.release = v.release) AS regressions
          FROM (SELECT release FROM public.sentinel_releases
                UNION
                SELECT DISTINCT release FROM public.sentinel_events WHERE release IS NOT NULL) v
          LEFT JOIN public.sentinel_releases r ON r.release = v.release
         ORDER BY coalesce((SELECT max(e.received_at) FROM public.sentinel_events e WHERE e.release = v.release), r.registered_at) DESC NULLS LAST
         LIMIT greatest(1, least(coalesce(p_limit, 30), 200))
      ) x), '[]'::jsonb);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_release_list(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_release_list(integer) TO authenticated;

CREATE OR REPLACE FUNCTION public.sentinel_event_stack(p_event uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v jsonb;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT jsonb_build_object('event_id', e.id, 'release', e.release, 'stack', e.stack,
                            'has_maps', coalesce(r.map_files, 0) > 0)
    INTO v
    FROM public.sentinel_events e
    LEFT JOIN public.sentinel_releases r ON r.release = e.release
   WHERE e.id = p_event;
  RETURN v;
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_event_stack(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_event_stack(uuid) TO authenticated;
