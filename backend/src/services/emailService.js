const { Resend } = require('resend')
const resend = new Resend(process.env.RESEND_API_KEY)
const APP_URL = process.env.APP_URL || 'https://vulnexusai.com'

const baseStyle = `
  font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;
  background: #0a0a0a; color: #e0e0e0; border-radius: 8px; overflow: hidden;
`
const headerStyle = `
  background: #111; padding: 24px 32px; border-bottom: 1px solid #222;
`
const bodyStyle = `padding: 32px;`
const btnStyle = `
  display: inline-block; background: #7c3aed; color: #fff;
  padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600;
`

async function send(to, subject, html) {
  if (!process.env.RESEND_API_KEY) return; // Silent skip if no key
  return resend.emails.send({ from: process.env.EMAIL_FROM || 'noreply@vulnexusai.com', to, subject, html })
}

module.exports = {
  async sendWelcome(email) {
    return send(email, 'Bem-vindo ao VulnexusAI — Comece seu primeiro scan', `
      <div style="${baseStyle}">
        <div style="${headerStyle}"><strong>🛡️ VulnexusAI</strong></div>
        <div style="${bodyStyle}">
          <h2>Conta confirmada! 🎉</h2>
          <p>Sua conta está ativa. Você tem <strong>3 scans gratuitos por dia</strong> para detectar vulnerabilidades em suas APIs.</p>
          <a href="${APP_URL}" style="${btnStyle}">Fazer meu primeiro scan →</a>
          <p style="margin-top: 32px; font-size: 12px; color: #666;">
            VulnexusAI — Use apenas em APIs que você tem autorização para testar.
          </p>
        </div>
      </div>
    `)
  },

  async sendScanComplete(email, scanUrl, vulnCount, riskLevel, scanId) {
    const riskColor = riskLevel === 'critical' ? '#ef4444' : riskLevel === 'high' ? '#f97316' : '#22c55e'
    return send(email, `Scan de ${scanUrl} concluído — ${vulnCount} vulnerabilidade(s) encontrada(s)`, `
      <div style="${baseStyle}">
        <div style="${headerStyle}"><strong>🛡️ VulnexusAI</strong></div>
        <div style="${bodyStyle}">
          <h2>Scan concluído</h2>
          <p>URL: <code>${scanUrl}</code></p>
          <p>Risco: <strong style="color: ${riskColor}">${riskLevel?.toUpperCase()}</strong></p>
          <p>Vulnerabilidades encontradas: <strong>${vulnCount}</strong></p>
          <a href="${APP_URL}/dashboard.html" style="${btnStyle}">Ver resultado completo →</a>
        </div>
      </div>
    `)
  },

  async sendHighSeverityAlert(email, scanUrl, vulnName, recommendation) {
    return send(email, `🚨 Vulnerabilidade crítica detectada em ${scanUrl}`, `
      <div style="${baseStyle}">
        <div style="${headerStyle}"><strong>🛡️ VulnexusAI — Alerta de Segurança</strong></div>
        <div style="${bodyStyle}">
          <h2 style="color: #ef4444;">Vulnerabilidade crítica detectada</h2>
          <p>URL: <code>${scanUrl}</code></p>
          <p><strong>Vulnerabilidade:</strong> ${vulnName}</p>
          <p><strong>Recomendação:</strong> ${recommendation}</p>
          <a href="${APP_URL}/dashboard.html" style="${btnStyle}">Ver detalhes e corrigir →</a>
        </div>
      </div>
    `)
  },

  async sendDailyLimitWarning(email, used, limit) {
    return send(email, `Você usou ${used} de ${limit} scans hoje`, `
      <div style="${baseStyle}">
        <div style="${headerStyle}"><strong>🛡️ VulnexusAI</strong></div>
        <div style="${bodyStyle}">
          <h2>Você está quase no limite do dia</h2>
          <p>Usou <strong>${used} de ${limit}</strong> scans no plano Free hoje.</p>
          <p>Com o plano Pro você tem scans ilimitados, export de relatórios PDF e notificações em tempo real.</p>
          <a href="${APP_URL}/pricing.html" style="${btnStyle}">Ver plano Pro →</a>
        </div>
      </div>
    `)
  }
}
