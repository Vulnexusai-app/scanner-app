-- ============================================================
-- VulnexusAI — Índices de Performance
-- Execute no SQL Editor do Supabase
-- ============================================================

-- Índice em scans(user_id)
-- Acelera todas as queries que filtram por usuário
-- Ex: buscar histórico, contar scans do dia
CREATE INDEX IF NOT EXISTS idx_scans_user_id
  ON public.scans(user_id);

-- Índice em scans(created_at)
-- Acelera queries com filtro de data (contarScansHoje)
CREATE INDEX IF NOT EXISTS idx_scans_created_at
  ON public.scans(created_at DESC);

-- Índice composto — ainda mais rápido para contarScansHoje
-- Que filtra por user_id E created_at ao mesmo tempo
CREATE INDEX IF NOT EXISTS idx_scans_user_date
  ON public.scans(user_id, created_at DESC);
