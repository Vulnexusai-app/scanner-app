const supabase = require('../services/supabase')

async function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Não autenticado' })

  const { data: { user }, error: authErr } = await supabase.auth.getUser(token)
  if (authErr || !user) return res.status(401).json({ error: 'Token inválido' })

  const { data: admin } = await supabase
    .from('admin_users')
    .select('user_id')
    .eq('user_id', user.id)
    .single()

  if (!admin) return res.status(403).json({ error: 'Acesso negado' })

  req.user = user
  next()
}

module.exports = requireAdmin
