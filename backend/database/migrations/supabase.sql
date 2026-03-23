-- ============================================================
-- VulnexusAI SaaS — Schema do Banco de Dados
-- Execute no SQL Editor do Supabase (supabase.com → SQL Editor)
-- ============================================================

-- ── Tabela: users ─────────────────────────────────────────────
-- Armazena o plano de cada usuário (free ou pro)
-- O id vem do Supabase Auth automaticamente
CREATE TABLE IF NOT EXISTS public.users (
  id         UUID PRIMARY KEY,           -- mesmo ID do Supabase Auth
  email      TEXT NOT NULL UNIQUE,
  plan       TEXT NOT NULL DEFAULT 'free'
             CHECK (plan IN ('free', 'pro')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Tabela: scans ─────────────────────────────────────────────
-- Histórico de todos os scans feitos pelos usuários
CREATE TABLE IF NOT EXISTS public.scans (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  result     JSONB,                       -- resultado completo em JSON
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Índices para performance ──────────────────────────────────
-- Acelera buscas por usuário e por data
CREATE INDEX IF NOT EXISTS idx_scans_user_id    ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at DESC);

-- ── Row Level Security (RLS) ──────────────────────────────────
-- Cada usuário só enxerga seus próprios dados
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- Usuário vê apenas seu próprio perfil
CREATE POLICY "users_own" ON public.users
  FOR ALL USING (auth.uid() = id);

-- Usuário vê apenas seus próprios scans
CREATE POLICY "scans_own" ON public.scans
  FOR ALL USING (auth.uid() = user_id);

-- Service Role (backend) bypassa o RLS — pode ver tudo
CREATE POLICY "service_users" ON public.users
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_scans" ON public.scans
  FOR ALL TO service_role USING (true) WITH CHECK (true);
-- -- Tabela: user_plans ----------------------------------------\n-- Armazena o plano de cada usu�rio e limites\nCREATE TABLE IF NOT EXISTS public.user_plans (\n  user_id       UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,\n  plan          TEXT DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),\n  scans_per_day INTEGER DEFAULT 3,\n  max_history   INTEGER DEFAULT 10,\n  updated_at    TIMESTAMPTZ DEFAULT NOW()\n);\n\n-- -- Tabela: scan_usage ----------------------------------------\n-- Contador di�rio de scans por usu�rio\nCREATE TABLE IF NOT EXISTS public.scan_usage (\n  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,\n  user_id     UUID REFERENCES auth.users(id) ON DELETE CASCADE,\n  date        DATE NOT NULL DEFAULT CURRENT_DATE,\n  scan_count  INTEGER DEFAULT 0,\n  created_at  TIMESTAMPTZ DEFAULT NOW(),\n  UNIQUE(user_id, date)\n);\n\n-- -- Tabela: banned_users --------------------------------------\nCREATE TABLE IF NOT EXISTS public.banned_users (\n  user_id   UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,\n  banned_at TIMESTAMPTZ DEFAULT NOW(),\n  reason    TEXT\n);\n\n-- -- Tabela: admin_users ---------------------------------------\nCREATE TABLE IF NOT EXISTS public.admin_users (\n  user_id    UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,\n  created_at TIMESTAMPTZ DEFAULT NOW()\n);\n\n-- -- RLS para as novas tabelas ---------------------------------\nALTER TABLE public.user_plans  ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.scan_usage  ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.banned_users ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.admin_users  ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY 'service_user_plans' ON public.user_plans\n  FOR ALL TO service_role USING (true) WITH CHECK (true);\n\nCREATE POLICY 'service_scan_usage' ON public.scan_usage\n  FOR ALL TO service_role USING (true) WITH CHECK (true);\n\nCREATE POLICY 'service_banned' ON public.banned_users\n  FOR ALL TO service_role USING (true) WITH CHECK (true);\n\nCREATE POLICY 'service_admin' ON public.admin_users\n  FOR ALL TO service_role USING (true) WITH CHECK (true);\n\nCREATE POLICY 'user_own_plan' ON public.user_plans\n  FOR SELECT USING (auth.uid() = user_id);\n\nCREATE POLICY 'user_own_usage' ON public.scan_usage\n  FOR SELECT USING (auth.uid() = user_id);
