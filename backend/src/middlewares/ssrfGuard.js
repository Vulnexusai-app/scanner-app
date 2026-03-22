/**
 * Middleware de Proteção SSRF
 * Verifica a URL antes mesmo da autenticação ou rate limit
 */
function validarURL(url) {
  if (typeof url !== "string") return { valida: false, erro: "URL deve ser um texto" };
  url = url.trim();
  if (!url) return { valida: false, erro: "URL não pode ser vazia" };

  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol))
      return { valida: false, erro: "Apenas http/https permitidos" };

    const host = parsed.hostname.toLowerCase();
    const bloqueados = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"];
    if (bloqueados.includes(host))
      return { valida: false, erro: "URLs internas bloqueadas por segurança (SSRF)" };

    if (host.startsWith("169.254."))
      return { valida: false, erro: "IP link-local bloqueado (SSRF protection)" };

    if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host))
      return { valida: false, erro: "IPs de rede privada bloqueados (SSRF protection)" };

    return { valida: true, urlLimpa: url };
  } catch {
    return { valida: false, erro: "URL inválida — verifique o formato" };
  }
}

function ssrfGuard(req, res, next) {
  const { url } = req.body;
  if (!url) return res.status(400).json({ erro: "URL é obrigatória" });

  const { valida, erro } = validarURL(url);
  if (!valida) {
    return res.status(400).json({ erro });
  }
  
  next();
}

module.exports = ssrfGuard;
