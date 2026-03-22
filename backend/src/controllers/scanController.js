const { escanear } = require("../../scans/engine/scanner");
const { analisarComIA } = require("../../scans/analyzers/aiAnalyzer");
const db = require("../services/dbService");
const config = require("../config");
const { log } = require("../utils/logger");

const { LIMITES } = config;


async function startScan(req, res) {
  const { url } = req.body;
  // A URL já foi validada pelo middleware ssrfGuard
  const urlLimpa = url;

  try {
    const usuarioReq = req.user || req.usuario;
    if (!usuarioReq) {
      return res.status(401).json({ erro: "Autenticação necessária para realizar scans" });
    }
    const usuario = await db.buscarOuCriarUsuario(usuarioReq.id, usuarioReq.email);
    const limite = LIMITES[usuario.plan];

    if (limite !== Infinity) {
      const scansHoje = await db.contarScansHoje(usuarioReq.id);
      if (scansHoje >= limite) {
        log("warn", "limite_atingido", usuarioReq.email, `plano=${usuario.plan}`);
        return res.status(429).json({ erro: "Limite de scans atingido para hoje", plano: usuario.plan });
      }
    }

    log("info", "scan_iniciado", usuarioReq.email, `url=${urlLimpa}`);
    const relatorio = await escanear(urlLimpa);
    const { analise, provedor } = await analisarComIA(relatorio, config);

    // Resultado padronizado v5 (Extreme)
    const resultado = {
      url: urlLimpa,
      timestamp: new Date().toISOString(),
      contexto: relatorio.contexto,
      score: relatorio.score,
      nivel: relatorio.nivel,
      resumo: relatorio.resumo,
      vulnerabilidades: relatorio.vulnerabilidades,
      correlacoes: relatorio.correlacoes,
      analiseIA: analise,
      provedor_ia: provedor,
      
      // Retrocompatibilidade básica (se necessário)
      score_seguranca: relatorio.score,
      nivel_risco: relatorio.nivel,
      total_problemas: relatorio.resumo.criticas + relatorio.resumo.moderadas + relatorio.resumo.baixas
    };

    // Salvar no banco (fire-and-forget — não bloqueia resposta)
    db.salvarScan(usuarioReq.id, urlLimpa, resultado)
      .then((scanSaved) => {
        // Disparo de Email Transacional Após Scan
        const emailService = require('../services/emailService');
        
        emailService.sendScanComplete(usuarioReq.email, urlLimpa, relatorio.vulnerabilidades.length || 0, relatorio.nivel, 'history_id')
          .catch(e => log('error', 'email_scan_complete_failed', usuarioReq.email, e.message));

        const criticalVulns = relatorio.vulnerabilidades.filter(v => v.severity === 'critical' || v.severity === 'high' || v.severidade === 'critical' || v.severidade === 'high');
        if (criticalVulns.length > 0) {
          const vuln = criticalVulns[0];
          emailService.sendHighSeverityAlert(usuarioReq.email, urlLimpa, vuln.title || vuln.nome || vuln.name || 'Vulnerabilidade Crítica', vuln.recommendation || vuln.recomendacao || 'Mitigar imediatamente')
            .catch(e => log('error', 'email_high_severity_failed', usuarioReq.email, e.message));
        }
      })
      .catch(e => log("error", "salvar_scan_falhou", usuarioReq.email, e.message));

    return res.json(resultado);
  } catch (erro) {
    const email = req.user?.email || req.usuario?.email || "unknown";
    log("error", "scan_falhou", email, erro.message);
    return res.status(500).json({ erro: erro.message });
  }
}

async function getHistory(req, res) {
  try {
    const historico = await db.buscarHistorico(req.usuario.id);
    const formatado = historico.map(s => ({
      id: s.id,
      url: s.url,
      score: s.result?.score ?? s.result?.score_seguranca,
      nivel: s.result?.nivel ?? s.result?.nivel_risco,
      contexto: s.result?.contexto || "Desconhecido",
      total_problemas: s.result?.resumo?.criticas ? (s.result.resumo.criticas + s.result.resumo.moderadas + s.result.resumo.baixas) : (s.result?.total_problemas || 0),
      data: s.created_at,
    }));
    return res.json({ scans: formatado });
  } catch (erro) {
    return res.status(500).json({ erro: erro.message });
  }
}

module.exports = { startScan, getHistory };
