const express = require('express')
const router = express.Router()
const stripe = require('../services/stripeService')
const supabase = require('../services/supabase')
const { autenticar } = require('../middlewares/auth')
const config = require('../config')
const { log } = require('../utils/logger')

// ─── POST /api/billing/create-checkout ──────────────────────
router.post('/create-checkout', autenticar, async (req, res) => {
  try {
    const userId = req.usuario.id
    const email = req.usuario.email

    // Verificar se já é Pro
    const { data: plan } = await supabase
      .from('user_plans')
      .select('plan')
      .eq('user_id', userId)
      .single()

    if (plan?.plan === 'pro') {
      return res.status(400).json({ erro: 'Você já possui o plano Pro' })
    }

    // Buscar ou criar customer no Stripe
    let customerId = null
    const { data: userData } = await supabase
      .from('users')
      .select('stripe_customer_id')
      .eq('id', userId)
      .single()

    if (userData?.stripe_customer_id) {
      customerId = userData.stripe_customer_id
    } else {
      const customer = await stripe.customers.create({
        email,
        metadata: { supabase_user_id: userId }
      })
      customerId = customer.id
      await supabase
        .from('users')
        .update({ stripe_customer_id: customerId })
        .eq('id', userId)
    }

    // Criar sessão de checkout
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: config.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${config.APP_URL}/dashboard.html?upgrade=success`,
      cancel_url: `${config.APP_URL}/pricing.html?upgrade=cancelled`,
      metadata: { user_id: userId },
      subscription_data: { metadata: { user_id: userId } },
      payment_method_types: ['card'],
      locale: 'pt-BR',
    })

    log('info', 'checkout_created', email, `session=${session.id}`)
    res.json({ url: session.url })

  } catch (err) {
    log('error', 'checkout_error', req.usuario?.email, err.message)
    res.status(500).json({ erro: 'Erro ao criar checkout: ' + err.message })
  }
})

// ─── POST /api/billing/portal ────────────────────────────────
router.post('/portal', autenticar, async (req, res) => {
  try {
    const userId = req.usuario.id

    const { data: userData } = await supabase
      .from('users')
      .select('stripe_customer_id')
      .eq('id', userId)
      .single()

    if (!userData?.stripe_customer_id) {
      return res.status(400).json({ erro: 'Nenhuma assinatura encontrada' })
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: userData.stripe_customer_id,
      return_url: `${config.APP_URL}/dashboard.html`,
    })

    res.json({ url: session.url })
  } catch (err) {
    log('error', 'portal_error', req.usuario?.email, err.message)
    res.status(500).json({ erro: 'Erro ao abrir portal: ' + err.message })
  }
})

// ─── GET /api/billing/status ─────────────────────────────────
router.get('/status', autenticar, async (req, res) => {
  try {
    const { data: plan } = await supabase
      .from('user_plans')
      .select('plan, scans_per_day')
      .eq('user_id', req.usuario.id)
      .single()

    res.json({
      plan: plan?.plan || 'free',
      scans_per_day: plan?.scans_per_day || 3
    })
  } catch (err) {
    res.status(500).json({ erro: err.message })
  }
})

// ─── POST /api/billing/webhook ───────────────────────────────
// ATENÇÃO: esta rota precisa de raw body — configurado no app.js
router.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature']

  let event
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      config.STRIPE_WEBHOOK_SECRET
    )
  } catch (err) {
    log('error', 'webhook_signature_failed', '-', err.message)
    return res.status(400).json({ erro: `Webhook Error: ${err.message}` })
  }

  log('info', 'webhook_received', '-', `type=${event.type}`)

  try {
    switch (event.type) {

      case 'checkout.session.completed': {
        const session = event.data.object
        const userId = session.metadata?.user_id
        if (userId) {
          await atualizarPlano(userId, 'pro', 999)
          log('info', 'upgrade_pro', userId, `session=${session.id}`)
        }
        break
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object
        if (invoice.billing_reason === 'subscription_cycle') {
          const userId = await getUserIdByCustomer(invoice.customer)
          if (userId) await atualizarPlano(userId, 'pro', 999)
        }
        break
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object
        const userId = await getUserIdByCustomer(invoice.customer)
        log('warn', 'payment_failed', userId || invoice.customer, `attempt=${invoice.attempt_count}`)
        break
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object
        const userId = await getUserIdByCustomer(sub.customer)
        if (userId) {
          await atualizarPlano(userId, 'free', 3)
          log('info', 'downgrade_free', userId)
        }
        break
      }

      case 'customer.subscription.updated': {
        const sub = event.data.object
        const userId = await getUserIdByCustomer(sub.customer)
        if (userId) {
          if (sub.status === 'active') {
            await atualizarPlano(userId, 'pro', 999)
          } else if (['canceled', 'incomplete_expired', 'unpaid'].includes(sub.status)) {
            await atualizarPlano(userId, 'free', 3)
          }
        }
        break
      }
    }

    res.json({ received: true })

  } catch (err) {
    log('error', 'webhook_processing_error', '-', err.message)
    res.json({ received: true, warning: err.message })
  }
})

// ── Helpers ───────────────────────────────────────────────────
async function atualizarPlano(userId, plano, scansPerDay) {
  await supabase.from('user_plans').upsert({
    user_id: userId,
    plan: plano,
    scans_per_day: scansPerDay,
    updated_at: new Date().toISOString()
  }, { onConflict: 'user_id' })
}

async function getUserIdByCustomer(customerId) {
  const { data } = await supabase
    .from('users')
    .select('id')
    .eq('stripe_customer_id', customerId)
    .single()
  return data?.id || null
}

module.exports = router
