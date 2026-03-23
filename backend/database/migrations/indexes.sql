-- ============================================================
-- VulnexusAI SaaS — Índices de Performance
-- Execute no SQL Editor do Supabase para otimização
-- ============================================================

-- Scans: Busca rápida por usuário e data (Dashboard e Histórico)
CREATE INDEX IF NOT EXISTS idx_scans_user_id_created_at ON public.scans(user_id, created_at DESC);

-- Scan Usage: Busca rápida por data para métricas globais (Admin)
CREATE INDEX IF NOT EXISTS idx_scan_usage_date ON public.scan_usage(date);

-- User Plans: Acesso rápido aos limites do usuário
CREATE INDEX IF NOT EXISTS idx_user_plans_user_id ON public.user_plans(user_id);

-- Busca por URL (Opcional, se houver busca global)
CREATE INDEX IF NOT EXISTS idx_scans_url ON public.scans(url);
