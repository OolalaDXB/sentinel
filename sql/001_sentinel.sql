-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel — schéma de référence, version 1.
--
-- Installé tel quel dans la base de l'hôte, APRÈS que l'hôte a défini :
--   public.sentinel_host_tenant(p_claimed uuid, p_user uuid) RETURNS uuid
-- qui rend la boutique (le « tenant ») d'un événement, ou NULL : l'hôte seul
-- sait si un utilisateur appartient à une boutique. La boutique prétendue par
-- le navigateur n'est JAMAIS crue sans ce contrôle.
--
-- Aucune lecture ni écriture pour `anon` / `authenticated` : l'écriture passe
-- par `sentinel_ingest` (service_role, appelée par la fonction de réception),
-- la lecture par les fonctions d'administration de l'hôte.
-- Ce fichier ne contient aucun mot de suppression : une purge, quand elle
-- viendra, sera une migration à part.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sentinel_issues (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  fingerprint text NOT NULL UNIQUE,
  error_type text NOT NULL CHECK (error_type IN ('permission_denied', 'database', 'edge_function', 'network', 'render', 'javascript', 'unknown')),
  title text NOT NULL,
  code text,
  status text NOT NULL DEFAULT 'unresolved' CHECK (status IN ('unresolved', 'in_progress', 'resolved', 'ignored')),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  event_count bigint NOT NULL DEFAULT 0,
  first_release text,
  last_release text,
  surfaces text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS sentinel_issues_last_seen_idx ON public.sentinel_issues (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS public.sentinel_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id uuid NOT NULL REFERENCES public.sentinel_issues(id),
  received_at timestamptz NOT NULL DEFAULT now(),
  occurred_at timestamptz NOT NULL,
  release text,
  environment text NOT NULL,
  surface text NOT NULL CHECK (surface IN ('erp', 'portal', 'pos', 'site', 'admin', 'edge', 'unknown')),
  error_type text NOT NULL,
  error_name text,
  message text NOT NULL,
  code text,
  details text,
  hint text,
  stack text,
  url text,
  tenant_id uuid,
  user_id uuid,
  breadcrumbs jsonb NOT NULL DEFAULT '[]'::jsonb,
  context jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS sentinel_events_issue_idx ON public.sentinel_events (issue_id, received_at DESC);
CREATE INDEX IF NOT EXISTS sentinel_events_received_idx ON public.sentinel_events (received_at DESC);
CREATE INDEX IF NOT EXISTS sentinel_events_tenant_idx ON public.sentinel_events (tenant_id);

-- Limite de débit : une ligne par clé (utilisateur, ou empreinte d'adresse IP),
-- fenêtre d'une minute remise à zéro sur place.
CREATE TABLE IF NOT EXISTS public.sentinel_rate_limits (
  bucket_key text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  hits integer NOT NULL
);

ALTER TABLE public.sentinel_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_rate_limits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_issues, public.sentinel_events, public.sentinel_rate_limits FROM PUBLIC, anon, authenticated;

-- Un coup de compteur pour une clé ; rend vrai si la limite est dépassée.
CREATE OR REPLACE FUNCTION public.sentinel_rate_hit(p_key text, p_limit integer)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_window timestamptz := date_trunc('minute', now());
  v_hits integer;
BEGIN
  INSERT INTO public.sentinel_rate_limits AS r (bucket_key, window_start, hits)
  VALUES (p_key, v_window, 1)
  ON CONFLICT (bucket_key) DO UPDATE
     SET hits = CASE WHEN r.window_start = v_window THEN r.hits + 1 ELSE 1 END,
         window_start = v_window
  RETURNING hits INTO v_hits;
  RETURN v_hits > p_limit;
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_rate_hit(text, integer) FROM PUBLIC, anon, authenticated;

-- Réception d'un événement DÉJÀ validé et nettoyé par la fonction de réception
-- (le format est revérifié ici : la base ne croit pas plus l'appelant).
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
  v_claimed uuid;
  v_tenant uuid;
  v_issue uuid;
  v_new boolean;
  v_event uuid;
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

  INSERT INTO public.sentinel_issues AS i (fingerprint, error_type, title, code, first_release, last_release, surfaces, event_count)
  VALUES (v_fingerprint, v_type, left(v_message, 200), v_err->>'code', p_event->>'release', p_event->>'release', ARRAY[v_surface], 1)
  ON CONFLICT (fingerprint) DO UPDATE
     SET last_seen_at = now(),
         event_count = i.event_count + 1,
         last_release = coalesce(EXCLUDED.last_release, i.last_release),
         surfaces = CASE WHEN v_surface = ANY (i.surfaces) THEN i.surfaces ELSE i.surfaces || v_surface END
  RETURNING id, (xmax = 0) INTO v_issue, v_new;

  INSERT INTO public.sentinel_events (
    issue_id, occurred_at, release, environment, surface, error_type, error_name, message,
    code, details, hint, stack, url, tenant_id, user_id, breadcrumbs, context)
  VALUES (
    v_issue,
    coalesce(nullif(p_event->>'occurred_at', '')::timestamptz, now()),
    p_event->>'release',
    coalesce(p_event->>'environment', 'production'),
    v_surface, v_type, v_err->>'name', v_message,
    v_err->>'code', v_err->>'details', v_err->>'hint', v_err->>'stack',
    p_event->>'url', v_tenant, p_user,
    CASE WHEN jsonb_typeof(p_event->'breadcrumbs') = 'array' THEN p_event->'breadcrumbs' ELSE '[]'::jsonb END,
    CASE WHEN jsonb_typeof(p_event->'context') = 'object' THEN p_event->'context' ELSE '{}'::jsonb END)
  RETURNING id INTO v_event;

  RETURN jsonb_build_object('accepted', true, 'issue_id', v_issue, 'event_id', v_event, 'new_issue', v_new, 'tenant_id', v_tenant);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_ingest(jsonb, text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_ingest(jsonb, text, uuid) TO service_role;
