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
