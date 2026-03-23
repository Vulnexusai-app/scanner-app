const express = require('express')
const router = express.Router()
const supabase = require('../services/supabase')
const requireAdmin = require('../middlewares/requireAdmin')

router.use(requireAdmin)

// Métricas gerais
router.get('/metrics', async (req, res) => {
  const today = new Date().toISOString().split('T')[0]
  const [
    { count: totalUsers },
    { count: scansToday },
    { count: totalScans },
    { data: planDist }
  ] = await Promise.all([
    supabase.from('users').select('id', { count: 'exact', head: true }), // note: requires special view or auth.users access via RPC
    supabase.from('scan_usage').select('scan_count', { count: 'exact', head: true }).eq('date', today),
    supabase.from('scans').select('id', { count: 'exact', head: true }),
    supabase.from('user_plans').select('plan')
  ])

  const planCounts = (planDist ?? []).reduce((acc, row) => {
    acc[row.plan] = (acc[row.plan] ?? 0) + 1
    return acc
  }, {})

  res.json({ totalUsers, scansToday, totalScans, planCounts })
})

// Listar usuários
router.get('/users', async (req, res) => {
  const { data, error } = await supabase.auth.admin.listUsers({ page: 1, perPage: 50 })
  if (error) return res.status(500).json({ error: error.message })
  res.json(data)
})

// Banir usuário
router.post('/ban-user/:userId', async (req, res) => {
  const { userId } = req.params
  const { reason } = req.body

  await supabase.from('banned_users').upsert({ user_id: userId, reason: reason ?? 'Violação dos termos' })

  // Revogar todas as sessões do usuário
  await supabase.auth.admin.signOut(userId, 'global')

  res.json({ message: 'Usuário banido com sucesso' })
})

module.exports = router
