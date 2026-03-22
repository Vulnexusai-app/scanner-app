-- Tabela para configuração de MFA (Multi-Factor Authentication)
CREATE TABLE IF NOT EXISTS user_mfa (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  secret TEXT NOT NULL, -- Secret TOTP base32
  backup_codes TEXT[] DEFAULT '{}', -- Array de códigos de backup
  enabled BOOLEAN DEFAULT false, -- MFA ativo ou não
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa(user_id);
CREATE INDEX IF NOT EXISTS idx_user_mfa_enabled ON user_mfa(enabled);

-- RLS (Row Level Security) para multi-tenant
ALTER TABLE user_mfa ENABLE ROW LEVEL SECURITY;

-- Política: Usuários só podem ver/alterar próprio MFA
CREATE POLICY "Users can manage own MFA" ON user_mfa
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id);

-- Política: Serviço pode ler MFA para verificação
CREATE POLICY "Service can read MFA for verification" ON user_mfa
  FOR SELECT
  TO authenticated
  USING (true);
