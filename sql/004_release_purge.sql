-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — purge des source maps (version 4).
--
-- Une version garde ses maps tant qu'elles peuvent servir à lire une pile :
--   - elle est parmi les `p_keep_latest` dernières inscrites (10 par défaut,
--     3 au moins) ;
--   - elle a été inscrite il y a moins de `p_min_age_days` jours (14 par
--     défaut, 7 au moins) : un onglet resté ouvert sur une ancienne version
--     peut encore envoyer une erreur ;
--   - un événement de cette version existe encore (les événements vivent 90
--     jours, `sentinel_purge`) : sa pile doit rester lisible.
-- Hors de ces trois cas, ses maps peuvent partir. La BASE décide qui
-- (`sentinel_release_purge_candidates`) ; l'hôte retire les fichiers de son
-- stockage, puis la base inscrit ce qui RESTE vraiment, relu par l'hôte
-- (`sentinel_release_mark_purged`) : `map_files` dit toujours le contenu du
-- stockage. La ligne de la version reste : ses comptes (problèmes nés,
-- régressions) gardent leur sens, ses piles sont dites illisibles. Une
-- version redéposée redevient lisible (`sentinel_release_register`).
-- Service seul, aucun droit client.
--
-- Aucun mot de suppression dans ce fichier.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE public.sentinel_releases ADD COLUMN IF NOT EXISTS purged_at timestamptz;

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
     SET map_files = EXCLUDED.map_files, map_bytes = EXCLUDED.map_bytes,
         registered_at = now(), purged_at = NULL;
  RETURN jsonb_build_object('release', p_release, 'map_files', p_files);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_release_register(text, integer, bigint) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_release_register(text, integer, bigint) TO service_role;

CREATE OR REPLACE FUNCTION public.sentinel_release_purge_candidates(
  p_keep_latest integer DEFAULT 10,
  p_min_age_days integer DEFAULT 14,
  p_limit integer DEFAULT 20)
 RETURNS TABLE (release text, map_files integer, map_bytes bigint, registered_at timestamptz)
 LANGUAGE sql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  WITH latest AS (
    SELECT r.release
      FROM public.sentinel_releases r
     ORDER BY r.registered_at DESC
     LIMIT greatest(coalesce(p_keep_latest, 10), 3)
  )
  SELECT r.release, r.map_files, r.map_bytes, r.registered_at
    FROM public.sentinel_releases r
   WHERE r.map_files > 0
     AND r.registered_at < now() - make_interval(days => greatest(coalesce(p_min_age_days, 14), 7))
     AND r.release NOT IN (SELECT l.release FROM latest l)
     AND NOT EXISTS (SELECT 1 FROM public.sentinel_events e WHERE e.release = r.release)
   ORDER BY r.registered_at
   LIMIT greatest(1, least(coalesce(p_limit, 20), 100));
$function$;
REVOKE ALL ON FUNCTION public.sentinel_release_purge_candidates(integer, integer, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_release_purge_candidates(integer, integer, integer) TO service_role;

CREATE OR REPLACE FUNCTION public.sentinel_release_mark_purged(p_release text, p_remaining_files integer, p_remaining_bytes bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_files integer := greatest(coalesce(p_remaining_files, 0), 0);
BEGIN
  UPDATE public.sentinel_releases
     SET map_files = v_files,
         map_bytes = greatest(coalesce(p_remaining_bytes, 0), 0),
         purged_at = CASE WHEN v_files = 0 THEN now() ELSE purged_at END
   WHERE release = p_release;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SENTINEL_RELEASE_UNKNOWN' USING ERRCODE = '22023';
  END IF;
  RETURN jsonb_build_object('release', p_release, 'map_files', v_files, 'purged', v_files = 0);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_release_mark_purged(text, integer, bigint) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_release_mark_purged(text, integer, bigint) TO service_role;
