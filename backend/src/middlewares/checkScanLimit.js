const supabase = require('../services/supabase')
const { log } = require('../utils/logger')

// Janela e limite iguais aos do Redis (1 scan por IP / hora) para anônimos.
// Fallback em memória usado quando o Redis não está disponível — garante que
// NUNCA liberamos um scan de anônimo sem limite de taxa.
const ANON_WINDOW_MS = 3600 * 1000 // 1 hora
const ANON_MAX = 1
const memoriaAnon = new Map() // ip -> { count, expiresAt }

function checkScanLimitMemoria(ip) {
  const agora = Date.now()
  const atual = memoriaAnon.get(ip)
  if (!atual || atual.expiresAt <= agora) {
    memoriaAnon.set(ip, { count: 1, expiresAt: agora + ANON_WINDOW_MS })
    return true
  }
  if (atual.count >= ANON_MAX) return false
  atual.count += 1
  return true
}

// Evita crescimento sem limite do fallback em memória: limpa entradas expiradas
// periodicamente (a cada 10 min). Processo único/legado — aceitável aqui.
setInterval(() => {
  const agora = Date.now()
  for (const [ip, entrada] of memoriaAnon) {
    if (entrada.expiresAt <= agora) memoriaAnon.delete(ip)
  }
}, 10 * 60 * 1000).unref()

async function checkScanLimit(req, res, next) {
  const authHeader = req.headers.authorization
  const token = authHeader?.split(' ')[1]

  // Usuário não autenticado: limite por IP via Redis (ou fallback em memória)
  if (!token) {
    const ip = req.ip
    const redis = req.app.get('redis')
    if (redis) {
      const key = `anon_scan:${ip}`
      try {
        const count = await redis.incr(key)
        if (count === 1) await redis.expire(key, 3600) // 1 hora
        if (count > ANON_MAX) {
          return res.status(429).json({
            error: 'Limite atingido',
            message: 'Crie uma conta gratuita para 3 scans por dia.',
            upgrade_url: `${process.env.APP_URL || 'https://vulnexusai.com'}/pricing.html`
          })
        }
      } catch (err) {
        log('error', 'rate_limit_redis_falhou', '-', err.message)
        return res.status(503).json({
          error: 'Serviço indisponível',
          message: 'Limitação de taxa temporariamente indisponível. Tente novamente em instantes.'
        })
      }
    } else {
      // Sem Redis: usa o fallback em memória — aplica o MESMO limite,
      // nunca libera sem restrição.
      log('warn', 'rate_limit_sem_redis', '-', 'usando fallback em memória p/ anônimos')
      if (!checkScanLimitMemoria(ip)) {
        return res.status(429).json({
          error: 'Limite atingido',
          message: 'Crie uma conta gratuita para 3 scans por dia.',
          upgrade_url: `${process.env.APP_URL || 'https://vulnexusai.com'}/pricing.html`
        })
      }
    }
    return next()
  }

  // Usuário autenticado: verificar JWT e limite do plano
  const { data: { user }, error } = await supabase.auth.getUser(token)
  if (error || !user) return res.status(401).json({ error: 'Token inválido' })

  // Verificar se email foi confirmado
  if (!user.email_confirmed_at) {
    return res.status(403).json({
      error: 'Email não confirmado',
      message: 'Confirme seu email para usar o scanner.',
      action: 'resend_verification'
    })
  }

  // Verificar se está banido
  const { data: banned } = await supabase
    .from('banned_users')
    .select('user_id')
    .eq('user_id', user.id)
    .single()
  if (banned) return res.status(403).json({ error: 'Conta suspensa' })

  // Buscar plano do usuário (default: free / 3 scans por dia)
  const { data: plan } = await supabase
    .from('user_plans')
    .select('scans_per_day, plan')
    .eq('user_id', user.id)
    .single()
  const scansPerDay = plan?.scans_per_day ?? 3

  // Verificar/incrementar uso do dia
  const today = new Date().toISOString().split('T')[0]
  const { data: usage } = await supabase
    .from('scan_usage')
    .select('scan_count')
    .eq('user_id', user.id)
    .eq('date', today)
    .single()

  const currentCount = usage?.scan_count ?? 0
  if (currentCount >= scansPerDay) {
    return res.status(429).json({
      error: 'Limite diário atingido',
      message: `Você usou ${currentCount}/${scansPerDay} scans hoje.`,
      upgrade_url: `${process.env.APP_URL || 'https://vulnexusai.com'}/pricing.html`
    })
  }

  // Incrementar atomicamente
  await supabase.from('scan_usage').upsert({
    user_id: user.id,
    date: today,
    scan_count: currentCount + 1
  }, { onConflict: 'user_id,date' })

  // Aviso quando restar 1 scan (2º de 3)
  if (currentCount + 1 === scansPerDay - 1) {
    // Disparar email de aviso async (não bloqueia a requisição)
    try {
      const emailService = require('../services/emailService')
      emailService.sendDailyLimitWarning(user.email, currentCount + 1, scansPerDay)
        .catch(e => console.error('Email warning failed:', e))
    } catch (err) {
      console.error('emailService not configured yet', err)
    }
  }

  req.user = user
  req.userPlan = plan?.plan ?? 'free'
  next()
}

module.exports = checkScanLimit
