/**
 * Middleware de Proteção SSRF
 * Valida a URL resolvendo o hostname via DNS e conferindo os endereços IP
 * resultantes contra faixas privadas/loopback/link-local, cobrindo também
 * notações alternativas de IP e IPv6 (::1, fe80::/10, ::ffff:127.0.0.1).
 */
const { normalizaIP, isIPProibido } = require("../utils/ssrf");
const { lookup } = require("node:dns/promises");

const HOSTS_BLOQUEADOS = ["localhost", "0.0.0.0"];

function validarBaseURL(url) {
  if (typeof url !== "string") return { valida: false, erro: "URL deve ser um texto" };
  url = url.trim();
  if (!url) return { valida: false, erro: "URL não pode ser vazia" };

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { valida: false, erro: "URL inválida — verifique o formato" };
  }

  if (!["http:", "https:"].includes(parsed.protocol))
    return { valida: false, erro: "Apenas http/https permitidos" };

  const host = parsed.hostname.toLowerCase();
  if (!host) return { valida: false, erro: "URL sem hostname válido" };

  if (HOSTS_BLOQUEADOS.includes(host) || host.endsWith(".localhost"))
    return { valida: false, erro: "URLs internas bloqueadas por segurança (SSRF)" };

  // Nomes de host internos conhecidos (cloud metadata), mesmo que passem do DNS.
  if (/metadata\.google\.internal$/i.test(host) || host === "metadata" ||
      /\.internal\.cloudapp\.net$/i.test(host) || /\.internal$/i.test(host))
    return { valida: false, erro: "Hostname interno de cloud bloqueado (SSRF protection)" };

  return { valida: true, host, urlLimpa: url };
}

/**
 * Valida a URL sintaticamente e resolve o hostname, rejeitando qualquer
 * IP privado/loopback/link-local (incluindo notações alternativas e IPv6).
 */
async function validarURL(url) {
  const base = validarBaseURL(url);
  if (!base.valida) return base;

  const host = base.host;

  // Host já é um IP literal (ou notação alternativa) — bloqueia direto.
  const ipLiteral = normalizaIP(host);
  if (ipLiteral) {
    if (isIPProibido(host) || isIPProibido(ipLiteral)) {
      return { valida: false, erro: "Endereço IP privado/interno bloqueado por segurança (SSRF)" };
    }
    return { valida: true, urlLimpa: url, hostResolvido: [ipLiteral] };
  }

  try {
    const resultado = await lookup(host, { all: true, verbatim: true });
    const ips = (Array.isArray(resultado) ? resultado : []).map(a => a.address).map(ip => ip.replace(/^\[|\]$/g, ""));

    for (const ip of ips) {
      if (isIPProibido(ip)) {
        return { valida: false, erro: `O domínio resolve para endereço interno (${ip}) — bloqueado (SSRF)` };
      }
    }
    return { valida: true, urlLimpa: url, hostResolvido: ips };
  } catch (e) {
    return { valida: false, erro: e && e.message ? e.message : "Falha na validação SSRF" };
  }
}

async function ssrfGuard(req, res, next) {
  const { url } = req.body;
  if (!url) return res.status(400).json({ erro: "URL é obrigatória" });

  try {
    const { valida, erro, hostResolvido } = await validarURL(url);
    if (!valida) return res.status(400).json({ erro });

    // Encaminha os IPs já resolvidos para o engine evitar re-resolução.
    req.ssrf = { hostResolvido: hostResolvido || [] };
    next();
  } catch (e) {
    return res.status(500).json({ erro: e && e.message ? e.message : "Erro na proteção SSRF" });
  }
}

module.exports = ssrfGuard;
module.exports.validarURL = validarURL;
