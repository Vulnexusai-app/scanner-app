const express = require('express')
const router = express.Router()
const supabase = require('../services/supabase')

// Reenviar email de verificação
router.post('/resend-verification', async (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email obrigatório' })
  const { error } = await supabase.auth.resend({ type: 'signup', email })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ message: 'Email reenviado com sucesso' })
})

// Solicitar reset de senha
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email obrigatório' })
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${process.env.APP_URL || 'https://vulnexusai.com'}/reset-password.html`
  })
  res.json({ message: 'Se o email estiver cadastrado, você receberá as instruções.' })
})

// Atualizar senha (via token do link de reset)
router.post('/update-password', async (req, res) => {
  const { password, access_token } = req.body
  if (!password || password.length < 8) return res.status(400).json({ error: 'Senha deve ter pelo menos 8 caracteres' })

  const userSupabase = require('@supabase/supabase-js').createClient(
    process.env.SUPABASE_URL || 'https://example.supabase.co',
    process.env.SUPABASE_ANON_KEY || 'dummy_anon_key',
    { global: { headers: { Authorization: `Bearer ${access_token}` } } }
  )
  const { error } = await userSupabase.auth.updateUser({ password })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ message: 'Senha atualizada com sucesso' })
})

// Deletar conta (LGPD)
router.delete('/account', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Não autenticado' })
  const { data: { user } } = await supabase.auth.getUser(token)
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado' })

  // Deletar dados do usuário
  await Promise.all([
    supabase.from('scan_usage').delete().eq('user_id', user.id),
    supabase.from('user_plans').delete().eq('user_id', user.id),
    supabase.from('scans').delete().eq('user_id', user.id) // adapte ao nome real da tabela
  ])

  // Deletar usuário do Supabase Auth
  const { error } = await supabase.auth.admin.deleteUser(user.id)
  if (error) return res.status(500).json({ error: 'Erro ao deletar conta' })
  res.json({ message: 'Conta deletada com sucesso' })
})

module.exports = router
