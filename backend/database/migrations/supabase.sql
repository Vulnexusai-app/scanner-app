-- ============================================================
-- VulnexusAI SaaS — Schema do Banco de Dados
-- Execute no SQL Editor do Supabase (supabase.com → SQL Editor)
-- ============================================================

-- —— Tabela: users ————————————————————————————————————————————
-- Extensão dos dados de autenticação com plano e metadados
CREATE TABLE IF NOT EXISTS public.users (
  id         UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email      TEXT NOT NULL UNIQUE,
  plan       TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- —— Tabela: user_plans ————————————————————————————————————————
-- Configurações de limites por plano
CREATE TABLE IF NOT EXISTS public.user_plans (
  user_id       UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  plan          TEXT DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  scans_per_day INTEGER DEFAULT 3,
  max_history   INTEGER DEFAULT 10,
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- —— Tabela: scan_usage ————————————————————————————————————————
-- Contador diário de utilização
CREATE TABLE IF NOT EXISTS public.scan_usage (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID REFERENCES public.users(id) ON DELETE CASCADE,
  date        DATE NOT NULL DEFAULT CURRENT_DATE,
  scan_count  INTEGER DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, date)
);

-- —— Tabela: scans —————————————————————————————————————————————
-- Histórico de scans realizados
CREATE TABLE IF NOT EXISTS public.scans (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  result     JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- —— Tabelas Administrativas ———————————————————————————————————
CREATE TABLE IF NOT EXISTS public.banned_users (
  user_id   UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  banned_at TIMESTAMPTZ DEFAULT NOW(),
  reason    TEXT
);

CREATE TABLE IF NOT EXISTS public.admin_users (
  user_id    UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- —— Índices ———————————————————————————————————————————————————
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_usage_user_date ON public.scan_usage(user_id, date);

-- —— Habilitar Row Level Security (RLS) ————————————————————————
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.banned_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;

-- —— Políticas RLS: Service Role (Backend) —————————————————————
CREATE POLICY "service_full_access_users" ON public.users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_plans" ON public.user_plans FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_usage" ON public.scan_usage FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_scans" ON public.scans FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_banned" ON public.banned_users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_full_access_admin" ON public.admin_users FOR ALL TO service_role USING (true) WITH CHECK (true);

-- —— Políticas RLS: Usuários Autenticados ——————————————————————
-- Usuários podem ver apenas seus próprios dados
CREATE POLICY "users_own_profile" ON public.users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "user_own_plan" ON public.user_plans FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "user_own_usage" ON public.scan_usage FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "scans_own_history" ON public.scans FOR ALL USING (auth.uid() = user_id);

-- Usuários podem checar se estão banidos (opcional, mas seguro)
CREATE POLICY "user_check_banned" ON public.banned_users FOR SELECT USING (auth.uid() = user_id);

