-- ════════════════════════════════════════════════════════════════════════════
-- Sentinel, module « guard » (version 1) : les rapports d'un garde de RLS.
--
-- Le module ne lit qu'une SORTIE : un fichier au format EXACT
-- `rls-guard-evidence/1` (verdict pass | block, invariants I1…I4 et STATE,
-- violations en TEXTE, exceptions en vigueur et périmées). Il ne connaît ni
-- l'outil qui l'a produit, ni l'hôte, ni ses tables.
--
-- Trois règles qui ne se discutent pas :
--   - un passage en ERREUR (code de sortie 2) n'a ni rapport ni verdict : il
--     s'inscrit `error`, jamais `pass` ;
--   - un invariant `not-run` (STATE sans référence) n'est jamais un succès ;
--   - une violation n'a pas d'identifiant : son empreinte est l'invariant et
--     son TEXTE normalisé (nombres isolés, UUID, empreintes hexadécimales
--     neutralisés — jamais un chiffre DANS un nom : `fonction_v3` reste
--     `fonction_v3`).
-- Cycle de vie : une violation NOUVELLE, qui REVIENT après une absence, ou dont
-- le problème a été résolu, passe par `sentinel_ingest` sous
-- `guard_finding:<empreinte>` (régression comprise) ; absente d'un passage
-- qui a évalué son invariant, elle est marquée « absente depuis » ce passage,
-- jamais résolue d'office. Un verdict `block` qui apporte du nouveau (ou
-- succède à un passage non bloquant) alerte par `sentinel_host_alert('guard_block')`.
-- Une exception périmée est COMPTÉE et montrée, jamais bloquante.
--
-- Crochet FACULTATIF de l'hôte, pour la vue d'ensemble :
--   public.sentinel_host_guard_history()
--     RETURNS TABLE (source text, verdict text, run_at timestamptz, summary jsonb, run_url text)
--   le dernier verdict de chacun des contrôles que l'hôte tenait déjà.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sentinel_guard_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- L'ordre de réception, strict : deux passages reçus à la même heure ne s'échangent pas.
  seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  run_key text NOT NULL UNIQUE CHECK (length(run_key) BETWEEN 1 AND 120),
  received_at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL CHECK (status IN ('pass', 'block', 'error')),
  verdict text CHECK (verdict IN ('pass', 'block')),
  exit_code integer NOT NULL CHECK (exit_code IN (0, 1, 2)),
  run_url text CHECK (run_url IS NULL OR (run_url ~ '^https://' AND length(run_url) <= 500)),
  event text CHECK (event IS NULL OR length(event) <= 40),
  commit_sha text CHECK (commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{7,64}$'),
  config_hash text CHECK (config_hash IS NULL OR length(config_hash) <= 128),
  tool_version text CHECK (tool_version IS NULL OR length(tool_version) <= 40),
  postgres_version text CHECK (postgres_version IS NULL OR length(postgres_version) <= 80),
  generated_at timestamptz,
  invariants jsonb NOT NULL DEFAULT '{}'::jsonb,
  findings_count integer NOT NULL DEFAULT 0,
  exceptions_in_effect integer NOT NULL DEFAULT 0,
  exceptions_stale integer NOT NULL DEFAULT 0,
  exceptions jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT sentinel_guard_runs_error_has_no_verdict CHECK ((status = 'error') = (verdict IS NULL)),
  CONSTRAINT sentinel_guard_runs_status_is_verdict CHECK (status = 'error' OR status = verdict)
);

CREATE TABLE IF NOT EXISTS public.sentinel_guard_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL REFERENCES public.sentinel_guard_runs(id),
  fingerprint text NOT NULL,
  invariant text NOT NULL CHECK (invariant IN ('I1', 'I2', 'I3', 'I4', 'STATE')),
  message text NOT NULL CHECK (length(message) BETWEEN 1 AND 2000)
);
CREATE INDEX IF NOT EXISTS sentinel_guard_findings_run_idx ON public.sentinel_guard_findings (run_id);
CREATE INDEX IF NOT EXISTS sentinel_guard_findings_fp_idx ON public.sentinel_guard_findings (fingerprint);

-- L'état d'une violation d'un passage à l'autre.
CREATE TABLE IF NOT EXISTS public.sentinel_guard_finding_states (
  fingerprint text PRIMARY KEY,
  invariant text NOT NULL,
  message text NOT NULL,
  first_run_id uuid NOT NULL REFERENCES public.sentinel_guard_runs(id),
  last_seen_run_id uuid NOT NULL REFERENCES public.sentinel_guard_runs(id),
  absent_since_run_id uuid REFERENCES public.sentinel_guard_runs(id),
  issue_id uuid REFERENCES public.sentinel_issues(id)
);
CREATE INDEX IF NOT EXISTS sentinel_guard_finding_states_first_idx ON public.sentinel_guard_finding_states (first_run_id);
CREATE INDEX IF NOT EXISTS sentinel_guard_finding_states_last_idx ON public.sentinel_guard_finding_states (last_seen_run_id);
CREATE INDEX IF NOT EXISTS sentinel_guard_finding_states_absent_idx ON public.sentinel_guard_finding_states (absent_since_run_id);
CREATE INDEX IF NOT EXISTS sentinel_guard_finding_states_issue_idx ON public.sentinel_guard_finding_states (issue_id);

ALTER TABLE public.sentinel_guard_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_guard_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_guard_finding_states ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sentinel_guard_runs, public.sentinel_guard_findings, public.sentinel_guard_finding_states FROM PUBLIC, anon, authenticated;

-- Le texte d'une violation, sans ce qui change d'un passage à l'autre.
CREATE OR REPLACE FUNCTION public.sentinel_guard_normalize(p_message text)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT left(btrim(regexp_replace(regexp_replace(regexp_replace(regexp_replace(
           coalesce(p_message, ''),
           '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<uuid>', 'g'),
           '\m(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{12,}\M', '<hex>', 'g'),
           '\m[0-9]+\M', '#', 'g'),
           '\s+', ' ', 'g')), 1000)
$function$;

CREATE OR REPLACE FUNCTION public.sentinel_guard_fingerprint(p_invariant text, p_message text)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'public'
AS $function$
  SELECT 'guard_finding:' || p_invariant || ':' || left(md5(public.sentinel_guard_normalize(p_message)), 20)
$function$;

-- Réception (service seul). `p_run` : { run_key, exit_code, run_url, event } ;
-- `p_evidence` : le fichier, ou NULL pour un passage en erreur.
CREATE OR REPLACE FUNCTION public.sentinel_guard_ingest(p_run jsonb, p_evidence jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_key text := nullif(btrim(p_run->>'run_key'), '');
  v_exit integer;
  v_verdict text;
  v_run uuid;
  v_inv jsonb := '{}'::jsonb;
  v_ran text[] := '{}';
  inv jsonb;
  msg text;
  v_fp text;
  st public.sentinel_guard_finding_states%ROWTYPE;
  v_issue_status text;
  v_res jsonb;
  v_new integer := 0;
  v_returned integer := 0;
  v_absent integer := 0;
  v_count integer := 0;
  v_prev_status text;
  v_stale jsonb;
  v_in_effect jsonb;
BEGIN
  BEGIN
    v_exit := (p_run->>'exit_code')::integer;
  EXCEPTION WHEN OTHERS THEN
    v_exit := NULL;
  END;
  IF v_key IS NULL OR length(v_key) > 120 OR v_exit IS NULL OR v_exit NOT IN (0, 1, 2) THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'RUN_INVALID');
  END IF;
  IF EXISTS (SELECT 1 FROM public.sentinel_guard_runs WHERE run_key = v_key) THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'ALREADY_RECEIVED');
  END IF;
  SELECT status INTO v_prev_status FROM public.sentinel_guard_runs ORDER BY seq DESC LIMIT 1;

  -- Un passage en erreur : ni rapport, ni verdict, jamais un succès.
  IF v_exit = 2 THEN
    IF p_evidence IS NOT NULL THEN
      RETURN jsonb_build_object('accepted', false, 'reason', 'ERROR_RUN_HAS_EVIDENCE');
    END IF;
    INSERT INTO public.sentinel_guard_runs (run_key, status, verdict, exit_code, run_url, event)
    VALUES (v_key, 'error', NULL, 2, nullif(p_run->>'run_url', ''), left(nullif(p_run->>'event', ''), 40))
    RETURNING id INTO v_run;
    RETURN jsonb_build_object('accepted', true, 'run_id', v_run, 'status', 'error');
  END IF;

  IF p_evidence IS NULL OR jsonb_typeof(p_evidence) <> 'object'
     OR (p_evidence->>'format') IS DISTINCT FROM 'rls-guard-evidence/1' THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'FORMAT_INVALID');
  END IF;
  IF length(p_evidence::text) > 2 * 1024 * 1024 THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'TOO_LARGE');
  END IF;
  v_verdict := p_evidence->>'verdict';
  IF v_verdict IS NULL OR v_verdict NOT IN ('pass', 'block') THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'VERDICT_INVALID');
  END IF;
  -- Le code de sortie et le verdict disent la même chose, sinon rien n'entre.
  IF (v_exit = 0) <> (v_verdict = 'pass') THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'VERDICT_EXIT_MISMATCH');
  END IF;
  IF jsonb_typeof(p_evidence->'invariants') IS DISTINCT FROM 'array' THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'INVARIANTS_INVALID');
  END IF;
  FOR inv IN SELECT * FROM jsonb_array_elements(p_evidence->'invariants') LOOP
    IF (inv->>'id') IS NULL OR (inv->>'id') NOT IN ('I1', 'I2', 'I3', 'I4', 'STATE')
       OR (inv->>'status') IS NULL OR (inv->>'status') NOT IN ('pass', 'fail', 'not-run')
       OR v_inv ? (inv->>'id')
       OR (jsonb_typeof(inv->'violations') IS DISTINCT FROM 'array')
       OR ((inv->>'status') = 'fail') <> (jsonb_array_length(inv->'violations') > 0) THEN
      RETURN jsonb_build_object('accepted', false, 'reason', 'INVARIANTS_INVALID');
    END IF;
    v_inv := v_inv || jsonb_build_object(inv->>'id', inv->>'status');
    IF (inv->>'status') IN ('pass', 'fail') THEN v_ran := v_ran || (inv->>'id'); END IF;
  END LOOP;
  -- Un verdict « pass » avec un invariant en échec : incohérent, refusé.
  IF v_verdict = 'pass' AND EXISTS (SELECT 1 FROM jsonb_each_text(v_inv) WHERE value = 'fail') THEN
    RETURN jsonb_build_object('accepted', false, 'reason', 'VERDICT_INCONSISTENT');
  END IF;

  v_stale := CASE WHEN jsonb_typeof(p_evidence#>'{exceptions,stale}') = 'array' THEN p_evidence#>'{exceptions,stale}' ELSE '[]'::jsonb END;
  v_in_effect := CASE WHEN jsonb_typeof(p_evidence#>'{exceptions,in_effect}') = 'array' THEN p_evidence#>'{exceptions,in_effect}' ELSE '[]'::jsonb END;

  INSERT INTO public.sentinel_guard_runs (run_key, status, verdict, exit_code, run_url, event, commit_sha, config_hash,
                                          tool_version, postgres_version, generated_at, invariants,
                                          exceptions_in_effect, exceptions_stale, exceptions)
  VALUES (v_key, v_verdict, v_verdict, v_exit, nullif(p_run->>'run_url', ''), left(nullif(p_run->>'event', ''), 40),
          lower(nullif(p_evidence->>'commit_sha', '')), left(p_evidence->>'config_hash', 128),
          left(p_evidence->>'tool_version', 40), left(p_evidence->>'postgres_server_version', 80),
          CASE WHEN (p_evidence->>'generated_at') ~ '^\d{4}-\d{2}-\d{2}T' THEN (p_evidence->>'generated_at')::timestamptz END,
          v_inv, jsonb_array_length(v_in_effect), jsonb_array_length(v_stale),
          jsonb_build_object('in_effect', v_in_effect, 'stale', v_stale))
  RETURNING id INTO v_run;

  -- Les violations de ce passage.
  FOR inv IN SELECT * FROM jsonb_array_elements(p_evidence->'invariants') LOOP
    FOR msg IN SELECT left(x, 2000) FROM jsonb_array_elements_text(inv->'violations') AS x WHERE length(btrim(x)) > 0 LOOP
      v_fp := public.sentinel_guard_fingerprint(inv->>'id', msg);
      CONTINUE WHEN EXISTS (SELECT 1 FROM public.sentinel_guard_findings f WHERE f.run_id = v_run AND f.fingerprint = v_fp);
      INSERT INTO public.sentinel_guard_findings (run_id, fingerprint, invariant, message) VALUES (v_run, v_fp, inv->>'id', msg);
      v_count := v_count + 1;
      SELECT * INTO st FROM public.sentinel_guard_finding_states WHERE fingerprint = v_fp FOR UPDATE;
      v_issue_status := (SELECT i.status FROM public.sentinel_issues i WHERE i.id = st.issue_id);
      IF st.fingerprint IS NULL OR st.absent_since_run_id IS NOT NULL OR v_issue_status = 'resolved' THEN
        v_res := public.sentinel_ingest(jsonb_build_object(
          'v', 1, 'fingerprint', v_fp, 'occurred_at', now(), 'release', left(p_evidence->>'commit_sha', 12),
          'environment', 'production', 'surface', 'unknown',
          'error', jsonb_build_object('type', 'permission_denied', 'name', 'GuardFinding',
                     'message', left('RLS Guard ' || (inv->>'id') || ' : ' || msg, 1000), 'code', 'GUARD_' || (inv->>'id')),
          'url', NULL, 'claimed_tenant', NULL, 'breadcrumbs', '[]'::jsonb,
          'context', jsonb_build_object('invariant', inv->>'id', 'run_key', v_key, 'verdict', v_verdict)),
          'guard:' || v_key, NULL);
        IF st.fingerprint IS NULL THEN v_new := v_new + 1; ELSE v_returned := v_returned + 1; END IF;
      END IF;
      INSERT INTO public.sentinel_guard_finding_states AS s (fingerprint, invariant, message, first_run_id, last_seen_run_id, absent_since_run_id, issue_id)
      VALUES (v_fp, inv->>'id', msg, v_run, v_run, NULL, (SELECT id FROM public.sentinel_issues WHERE fingerprint = v_fp))
      ON CONFLICT (fingerprint) DO UPDATE
         SET message = EXCLUDED.message, last_seen_run_id = v_run, absent_since_run_id = NULL,
             issue_id = coalesce(EXCLUDED.issue_id, s.issue_id);
    END LOOP;
  END LOOP;

  -- Absentes : seulement si leur invariant a été ÉVALUÉ par ce passage.
  UPDATE public.sentinel_guard_finding_states
     SET absent_since_run_id = v_run
   WHERE last_seen_run_id <> v_run AND absent_since_run_id IS NULL AND invariant = ANY (v_ran);
  GET DIAGNOSTICS v_absent = ROW_COUNT;

  UPDATE public.sentinel_guard_runs SET findings_count = v_count WHERE id = v_run;

  -- Bloquant : une alerte si le passage apporte du nouveau ou succède à un passage non bloquant.
  IF v_verdict = 'block' AND (v_new + v_returned > 0 OR v_prev_status IS DISTINCT FROM 'block') THEN
    BEGIN
      PERFORM public.sentinel_host_alert('guard_block', NULL, jsonb_build_object(
        'run_key', v_key, 'run_url', p_run->>'run_url', 'commit_sha', p_evidence->>'commit_sha',
        'findings', v_count, 'new_findings', v_new, 'returned_findings', v_returned,
        'invariants', v_inv, 'exceptions_stale', jsonb_array_length(v_stale)));
    EXCEPTION WHEN OTHERS THEN
      NULL;  -- Une alerte ratée ne fait pas perdre le passage.
    END;
  END IF;

  RETURN jsonb_build_object('accepted', true, 'run_id', v_run, 'status', v_verdict, 'findings', v_count,
    'new', v_new, 'returned', v_returned, 'absent', v_absent, 'stale_exceptions', jsonb_array_length(v_stale));
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_guard_ingest(jsonb, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.sentinel_guard_ingest(jsonb, jsonb) TO service_role;

-- Vue d'ensemble (exploitant) : le dernier passage, ses invariants, ses
-- violations (présentes et absentes), ses exceptions, les passages récents,
-- et les verdicts des contrôles que l'hôte tenait déjà.
CREATE OR REPLACE FUNCTION public.sentinel_guard_overview(p_runs integer DEFAULT 20)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  r public.sentinel_guard_runs%ROWTYPE;
  v_last_eval public.sentinel_guard_runs%ROWTYPE;
  v_history jsonb := '[]'::jsonb;
BEGIN
  IF NOT coalesce(public.sentinel_host_is_operator(), false) THEN
    RAISE EXCEPTION 'SENTINEL_NOT_OPERATOR' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO r FROM public.sentinel_guard_runs ORDER BY seq DESC LIMIT 1;
  SELECT * INTO v_last_eval FROM public.sentinel_guard_runs WHERE status <> 'error' ORDER BY seq DESC LIMIT 1;
  IF to_regprocedure('public.sentinel_host_guard_history()') IS NOT NULL THEN
    EXECUTE 'SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.source), ''[]''::jsonb) FROM public.sentinel_host_guard_history() h'
       INTO v_history;
  END IF;
  RETURN jsonb_build_object(
    'last_run', CASE WHEN r.id IS NULL THEN NULL ELSE to_jsonb(r) END,
    'last_evaluated_run', CASE WHEN v_last_eval.id IS NULL THEN NULL ELSE to_jsonb(v_last_eval) END,
    'findings', coalesce((SELECT jsonb_agg(jsonb_build_object(
        'fingerprint', s.fingerprint, 'invariant', s.invariant, 'message', s.message,
        'first_seen', (SELECT received_at FROM public.sentinel_guard_runs WHERE id = s.first_run_id),
        'last_seen', (SELECT received_at FROM public.sentinel_guard_runs WHERE id = s.last_seen_run_id),
        'absent_since', (SELECT jsonb_build_object('run_id', g.id, 'received_at', g.received_at, 'commit_sha', g.commit_sha, 'run_url', g.run_url)
                           FROM public.sentinel_guard_runs g WHERE g.id = s.absent_since_run_id),
        'issue_id', s.issue_id,
        'issue_status', (SELECT i.status FROM public.sentinel_issues i WHERE i.id = s.issue_id))
      ORDER BY (s.absent_since_run_id IS NOT NULL), s.invariant, s.message) FROM public.sentinel_guard_finding_states s), '[]'::jsonb),
    'runs', coalesce((SELECT jsonb_agg(jsonb_build_object(
        'id', g.id, 'received_at', g.received_at, 'status', g.status, 'commit_sha', g.commit_sha, 'event', g.event,
        'run_url', g.run_url, 'findings_count', g.findings_count, 'exceptions_stale', g.exceptions_stale, 'invariants', g.invariants)
      ORDER BY g.seq DESC) FROM (SELECT * FROM public.sentinel_guard_runs ORDER BY seq DESC
                                          LIMIT greatest(1, least(coalesce(p_runs, 20), 100))) g), '[]'::jsonb),
    'host_history', v_history);
END;
$function$;
REVOKE ALL ON FUNCTION public.sentinel_guard_overview(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.sentinel_guard_overview(integer) TO authenticated;
