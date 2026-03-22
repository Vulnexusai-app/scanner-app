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
    if (!["http:", "https:"].includes(parsed.protocol)) return { valida: false, erro: "Apenas http/https permitidos" };
    const host = parsed.hostname.toLowerCase();
    const bloqueados = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
    if (bloqueados.includes(host)) return { valida: false, erro: "URLs internas não permitidas" };
    if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return { valida: false, erro: "IPs privados não permitidos" };
    return { valida: true, urlLimpa: url };
  } catch {
    return { valida: false, erro: "URL inválida" };
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
        return res.status(429).json({ erro: "Limite de scans atingido", plano: usuario.plan });
      }
    }

    log("info", "scan_iniciado", req.usuario.email, `url=${urlLimpa}`);
    const relatorio = await escanear(urlLimpa);
    const { analise, provedor } = await analisarComIA(relatorio, config);

    const resultado = {
      scan: relatorio,
      analise,
      provedor_ia: provedor,
      nivel_risco: relatorio.nivel_risco,
      timestamp: new Date().toISOString(),
    };

    db.salvarScan(req.usuario.id, urlLimpa, resultado).catch(e => log("error", "salvar_scan_falhou", req.usuario.email, e.message));

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
      score: s.result?.scan?.score_seguranca,
      nivel_risco: s.result?.scan?.nivel_risco,
      data: s.created_at,
    }));
    return res.json({ scans: formatado });
  } catch (erro) {
    return res.status(500).json({ erro: erro.message });
  }
}

module.exports = { startScan, getHistory };
