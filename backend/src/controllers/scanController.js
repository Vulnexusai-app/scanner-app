const { escanear } = require("../../scans/engine/scanner");
const { analisarComIA } = require("../../scans/analyzers/aiAnalyzer");
const db = require("../services/dbService");
const config = require("../config");
const { log } = require("../utils/logger");

const { LIMITES } = config;

function validarURL(url) {
  if (typeof url !== "string") return { valida: false, erro: "URL deve ser um texto" };
  if (url.length > 2048) return { valida: false, erro: "URL muito longa" };
  url = url.trim();
  if (!url) return { valida: false, erro: "URL não pode ser vazia" };

  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol))
      return { valida: false, erro: "Apenas http/https permitidos" };

    const host = parsed.hostname.toLowerCase();

    // Bloqueio SSRF — localhost e redes privadas
    const bloqueados = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"];
    if (bloqueados.includes(host))
      return { valida: false, erro: "URLs internas bloqueadas por segurança (SSRF)" };

    // Link-local AWS/GCP metadata
    if (host.startsWith("169.254."))
      return { valida: false, erro: "IP link-local bloqueado (SSRF protection)" };

    // Redes privadas RFC1918
    if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host))
      return { valida: false, erro: "IPs de rede privada bloqueados (SSRF protection)" };

    return { valida: true, urlLimpa: url };
  } catch {
    return { valida: false, erro: "URL inválida — verifique o formato" };
  }
}

async function startScan(req, res) {
  const { url } = req.body;
  if (!url) return res.status(400).json({ erro: "URL é obrigatória" });

  const { valida, erro: erroURL, urlLimpa } = validarURL(url);
  if (!valida) return res.status(400).json({ erro: erroURL });

  try {
    const usuario = await db.buscarOuCriarUsuario(req.usuario.id, req.usuario.email);
    const limite = LIMITES[usuario.plan];

    if (limite !== Infinity) {
      const scansHoje = await db.contarScansHoje(req.usuario.id);
      if (scansHoje >= limite) {
        log("warn", "limite_atingido", req.usuario.email, `plano=${usuario.plan}`);
        return res.status(429).json({ erro: "Limite de scans atingido para hoje", plano: usuario.plan });
      }
    }

    log("info", "scan_iniciado", req.usuario.email, `url=${urlLimpa}`);
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
    db.salvarScan(req.usuario.id, urlLimpa, resultado)
      .catch(e => log("error", "salvar_scan_falhou", req.usuario.email, e.message));

    return res.json(resultado);
  } catch (erro) {
    log("error", "scan_falhou", req.usuario.email, erro.message);
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
