-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — diagnostic de base automatique (version 5).
--
-- Un problème de base (`permission_denied`, `database`) reçoit, à son PREMIER
-- événement, un `db_context` : ce que l'hôte sait de l'objet en cause (règles
-- d'accès, droits, dernière migration qui l'a touché). L'hôte le fournit par
-- un crochet FACULTATIF :
--   public.sentinel_host_db_context(p_text text, p_resource text, p_seen_at timestamptz) RETURNS jsonb
--     p_text     : message, détail et indice de l'événement ;
--     p_resource : l'objet nommé par le SDK (refus de données), ou NULL ;
--     p_seen_at  : l'heure de l'événement.
-- Sans crochet, rien n'est rempli. Un crochet qui lève ne fait JAMAIS perdre
-- l'événement : le diagnostic est une sous-transaction, son échec est avalé.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS db_context jsonb;
ALTER TABLE public.sentinel_issues ADD COLUMN IF NOT EXISTS db_context_at timestamptz;

CREATE OR REPLACE FUNCTION public._sentinel_fill_db_context()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_ctx jsonb;
BEGIN
  IF NEW.error_type NOT IN ('permission_denied', 'database') THEN
    RETURN NULL;
  END IF;
  IF to_regprocedure('public.sentinel_host_db_context(text,text,timestamptz)') IS NULL THEN
    RETURN NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM public.sentinel_issues WHERE id = NEW.issue_id AND db_context IS NOT NULL) THEN
    RETURN NULL;
  END IF;
  BEGIN
    EXECUTE 'SELECT public.sentinel_host_db_context($1, $2, $3)'
       INTO v_ctx
      USING concat_ws(' ', NEW.message, NEW.details, NEW.hint),
            nullif(NEW.context->>'resource', ''),
            NEW.received_at;
    UPDATE public.sentinel_issues
       SET db_context = coalesce(v_ctx, '{}'::jsonb), db_context_at = now()
     WHERE id = NEW.issue_id;
  EXCEPTION WHEN OTHERS THEN
    -- Le diagnostic ne fait jamais perdre l'événement.
    NULL;
  END;
  RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION public._sentinel_fill_db_context() FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE TRIGGER trg_sentinel_events_db_context
  AFTER INSERT ON public.sentinel_events
  FOR EACH ROW EXECUTE FUNCTION public._sentinel_fill_db_context();
