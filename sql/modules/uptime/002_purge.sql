-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel, module « uptime » (version 2) : purge des vérifications HTTP.
--
-- `sentinel_http_checks_purge(jours)` retire les vérifications plus vieilles
-- que N jours (30 au moins, quoi qu'on demande), jamais un moniteur, jamais
-- une vérification EN ATTENTE de sa réponse. C'est la seule fonction du module
-- qui supprime : ce fichier contient le mot, il se pose donc sous l'enveloppe
-- de l'hôte quand son connecteur expire dessus.
-- ════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION public.sentinel_http_checks_purge(p_days integer DEFAULT 30)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_days integer := greatest(30, coalesce(p_days, 30));
  v_n integer;
BEGIN
  DELETE FROM public.sentinel_http_checks
   WHERE requested_at < now() - make_interval(days => v_days)
     AND healthy IS NOT NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN jsonb_build_object('purged', v_n, 'days', v_days);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_http_checks_purge(integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_http_checks_purge(integer) TO service_role;
