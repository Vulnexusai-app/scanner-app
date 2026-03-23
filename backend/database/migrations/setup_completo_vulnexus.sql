-- ============================================================
-- VulnexusAI SaaS — Schema Consolidado do Banco de Dados
-- Data de Criação: 2026-03-22
-- Instruções: Copie este conteúdo integralmente e cole no 
-- SQL Editor do seu projeto Supabase. Use o botão "Run".
-- ============================================================

-- ── 1. Tabelas Base ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.users (
  id         UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email      TEXT NOT NULL UNIQUE,
  plan       TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  stripe_customer_id TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.user_plans (
  user_id       UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  plan          TEXT DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  scans_per_day INTEGER DEFAULT 3,
  max_history   INTEGER DEFAULT 10,
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.scan_usage (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID REFERENCES public.users(id) ON DELETE CASCADE,
  date        DATE NOT NULL DEFAULT CURRENT_DATE,
  scan_count  INTEGER DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, date)
);

CREATE TABLE IF NOT EXISTS public.scans (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  result     JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.banned_users (
  user_id   UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  banned_at TIMESTAMPTZ DEFAULT NOW(),
  reason    TEXT
);

CREATE TABLE IF NOT EXISTS public.admin_users (
  user_id    UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── 2. Índices de Performance ────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_usage_user_date ON public.scan_usage(user_id, date);
CREATE INDEX IF NOT EXISTS idx_scans_user_id_created_at ON public.scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_usage_date ON public.scan_usage(date);
CREATE INDEX IF NOT EXISTS idx_user_plans_user_id ON public.user_plans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_url ON public.scans(url);
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON public.users(stripe_customer_id);

-- ── 3. Row Level Security (RLS) ───────────────────────────────

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.banned_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;

-- ── 4. Políticas RLS: Service Role (Backend) ──────────────────

CREATE POLICY "service_full_access_users" ON public.users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_plans" ON public.user_plans FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_usage" ON public.scan_usage FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_scans" ON public.scans FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_banned" ON public.banned_users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_admin" ON public.admin_users FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── 5. Políticas RLS: Usuários Autenticados ──────────────────

CREATE POLICY "users_own_profile" ON public.users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "user_own_plan" ON public.user_plans FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "user_own_usage" ON public.scan_usage FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "scans_own_history" ON public.scans FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "user_check_banned" ON public.banned_users FOR SELECT USING (auth.uid() = user_id);
