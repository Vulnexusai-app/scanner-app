-- Passo 6: Atualizar Schema para Stripe

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT UNIQUE;

CREATE INDEX IF NOT EXISTS idx_users_stripe_customer
ON public.users(stripe_customer_id);
