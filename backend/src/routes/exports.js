const express = require('express')
const router = express.Router()
const PDFDocument = require('pdfkit')
const supabase = require('../services/supabase')

// Helper para extrair user do JWT
async function getUser(req) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return null
  const { data: { user } } = await supabase.auth.getUser(token)
  return user
}

// Export JSON
router.get('/scans/:scanId/export/json', async (req, res) => {
  const user = await getUser(req)
  if (!user) return res.status(401).json({ error: 'Não autenticado' })

  const { data: scan, error } = await supabase
    .from('historico_scans') // Adaptação para a tabela provável do repositório
    .select('*')
    .eq('id', req.params.scanId)
    .eq('user_id', user.id)
    .single()

  if (error || !scan) return res.status(404).json({ error: 'Scan não encontrado' })

  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Content-Disposition', `attachment; filename="vulnexus-report-${scan.id}.json"`)
  res.json({
    generated_by: 'VulnexusAI',
    generated_at: new Date().toISOString(),
    scan_id: scan.id,
    url: scan.alvo || scan.url,
    scanned_at: scan.criado_em || scan.created_at,
    risk_level: scan.risk_level || scan.nivel_risco,
    risk_score: scan.risk_score || scan.pontuacao_risco,
    vulnerabilities: scan.vulnerabilities || scan.vulnerabilidades || [],
    headers_checked: scan.headers_checked || scan.headers_verificados || [],
    ai_analysis: scan.ai_analysis || scan.analise_ia || null
  })
})

// Export PDF
router.get('/scans/:scanId/export/pdf', async (req, res) => {
  const user = await getUser(req)
  if (!user) return res.status(401).json({ error: 'Não autenticado' })

  const { data: scan, error } = await supabase
    .from('historico_scans') // Adaptação para a tabela provável do repositório
    .select('*')
    .eq('id', req.params.scanId)
    .eq('user_id', user.id)
    .single()

  if (error || !scan) return res.status(404).json({ error: 'Scan não encontrado' })

  res.setHeader('Content-Type', 'application/pdf')
  res.setHeader('Content-Disposition', `attachment; filename="vulnexus-report-${scan.id}.pdf"`)

  const doc = new PDFDocument({ margin: 50 })
  doc.pipe(res)

  // Cabeçalho
  doc.fontSize(20).fillColor('#7c3aed').text('VulnexusAI', 50, 50)
  doc.fontSize(10).fillColor('#666').text('Relatório de Segurança de API', 50, 78)
  doc.moveTo(50, 100).lineTo(545, 100).strokeColor('#7c3aed').stroke()

  // Sumário
  doc.moveDown(2)
  doc.fontSize(14).fillColor('#000').text('Sumário Executivo')
  doc.moveDown(0.5)
  doc.fontSize(10).fillColor('#333')
  doc.text(`URL Analisada: ${scan.alvo || scan.url}`)
  doc.text(`Data do Scan: ${new Date(scan.criado_em || scan.created_at).toLocaleString('pt-BR')}`)
  doc.text(`Nível de Risco: ${(scan.nivel_risco || scan.risk_level || 'N/A').toUpperCase()}`)
  doc.text(`Score de Risco: ${scan.pontuacao_risco || scan.risk_score || 'N/A'}`)

  const vulns = scan.vulnerabilidades || scan.vulnerabilities || []
  const high = vulns.filter(v => v.severity === 'high' || v.severity === 'critical' || v.severidade === 'high' || v.severidade === 'critical').length
  const medium = vulns.filter(v => v.severity === 'medium' || v.severidade === 'medium').length
  const low = vulns.filter(v => v.severity === 'low' || v.severidade === 'low').length
  doc.moveDown(0.5)
  doc.text(`Vulnerabilidades: ${vulns.length} total — ${high} alta(s), ${medium} média(s), ${low} baixa(s)`)

  // Vulnerabilidades
  if (vulns.length > 0) {
    doc.moveDown(1.5)
    doc.fontSize(14).fillColor('#000').text('Vulnerabilidades Detectadas')
    doc.moveDown(0.5)
    vulns.forEach((v, i) => {
      const sev = v.severity || v.severidade || ''
      const color = sev === 'critical' || sev === 'high' ? '#dc2626'
                  : sev === 'medium' ? '#d97706' : '#16a34a'
      doc.fontSize(11).fillColor(color).text(`${i + 1}. [${sev.toUpperCase()}] ${v.name || v.nome || v.title || 'Vulnerabilidade'}`)
      doc.fontSize(9).fillColor('#333').text(`   ${v.description || v.descricao || ''}`, { indent: 20 })
      if (v.recommendation || v.recomendacao) {
        doc.fontSize(9).fillColor('#555').text(`   Recomendação: ${v.recommendation || v.recomendacao}`, { indent: 20 })
      }
      doc.moveDown(0.5)
    })
  }

  // Análise da IA
  const ai_analysis = scan.ai_analysis || scan.analise_ia
  if (ai_analysis) {
    doc.moveDown(1)
    doc.fontSize(14).fillColor('#000').text('Análise de Inteligência Artificial')
    doc.moveDown(0.5)
    doc.fontSize(9).fillColor('#333').text(ai_analysis, { lineGap: 4 })
  }

  // Rodapé
  doc.moveDown(2)
  doc.fontSize(8).fillColor('#999').text(
    `Gerado por VulnexusAI — ${process.env.APP_URL || 'https://vulnexusai.com'} — ${new Date().toLocaleDateString('pt-BR')}`,
    { align: 'center' }
  )

  doc.end()
})

module.exports = router
