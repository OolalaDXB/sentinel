-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — interrupteurs des modules (version 7) : `monitors`,
-- `weekly_digest`, `vitals_check`, `http_monitors`. Tous éteints par défaut ;
-- seul l'exploitant les change.
-- ════════════════════════════════════════════════════════════════════════════

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
  IF p_key IS NULL OR p_key NOT IN ('monitors', 'weekly_digest', 'vitals_check', 'http_monitors') OR p_enabled IS NULL THEN
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
  RETURN (SELECT jsonb_object_agg(k, coalesce((SELECT enabled FROM public.sentinel_settings s WHERE s.key = k), false))
            FROM unnest(ARRAY['monitors', 'weekly_digest', 'vitals_check', 'http_monitors']) AS k);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_settings_list() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_settings_list() TO authenticated;
