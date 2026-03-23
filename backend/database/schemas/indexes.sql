CREATE INDEX IF NOT EXISTS idx_scan_usage_user_date ON public.scan_usage(user_id, date);
CREATE INDEX IF NOT EXISTS idx_user_plans_user_id ON public.user_plans(user_id);
