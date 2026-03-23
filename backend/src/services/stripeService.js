const Stripe = require('stripe')
const config = require('../config')

if (!config.STRIPE_SECRET_KEY) {
  console.warn('[Stripe] STRIPE_SECRET_KEY não configurada')
}

const stripe = new Stripe(config.STRIPE_SECRET_KEY || 'dummy')

module.exports = stripe
