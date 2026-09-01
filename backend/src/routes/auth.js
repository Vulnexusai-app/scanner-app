const express = require('express')
const router = express.Router()
const supabase = require('../services/supabase')

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

module.exports = router
