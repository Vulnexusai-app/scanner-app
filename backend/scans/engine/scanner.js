const axios = require("axios");

function calcularScore(problemas) {
  if (problemas.length === 0) return 100;
  const penalidades = { HIGH: 20, MEDIUM: 10, LOW: 5 };
  let total = 100;
  for (const p of problemas) total -= penalidades[p.severidade] || 5;
  return Math.max(0, total);
}

function calcularNivelRisco(score) {
  if (score >= 80) return "LOW";
  if (score >= 50) return "MEDIUM";
  return "HIGH";
}

async function escanear(url) {
  const inicio = Date.now();

  try {
    const resposta = await axios.get(url, {
      timeout: 5000,
      validateStatus: () => true,
      headers: { "User-Agent": "VulnexusAI-Scanner/3.0" },
      maxRedirects: 5,
    });

    const tempoResposta = Date.now() - inicio;
    const headers = resposta.headers;
    const problemas = [];

    if (!headers["x-frame-options"]) {
      problemas.push({ tipo: "MISSING_HEADER", header: "X-Frame-Options", severidade: "MEDIUM",
        descricao: "Header ausente — site vulnerável a Clickjacking" });
    }
    if (!headers["content-security-policy"]) {
      problemas.push({ tipo: "MISSING_HEADER", header: "Content-Security-Policy", severidade: "HIGH",
        descricao: "Header ausente — site vulnerável a Cross-Site Scripting (XSS)" });
    }
    if (!headers["x-content-type-options"]) {
      problemas.push({ tipo: "MISSING_HEADER", header: "X-Content-Type-Options", severidade: "LOW",
        descricao: "Header ausente — navegador pode interpretar arquivos incorretamente" });
    }
    if (!headers["strict-transport-security"] && url.startsWith("https")) {
      problemas.push({ tipo: "MISSING_HEADER", header: "Strict-Transport-Security (HSTS)", severidade: "MEDIUM",
        descricao: "Header ausente — usuários podem ser redirecionados para HTTP inseguro" });
    }
    if (headers["access-control-allow-origin"] === "*") {
      problemas.push({ tipo: "CORS_MISCONFIGURATION", header: "Access-Control-Allow-Origin", severidade: "HIGH",
        descricao: "CORS permite qualquer origem (*) — qualquer site pode fazer requisições" });
    }
    if (headers["server"]) {
      problemas.push({ tipo: "SERVER_EXPOSURE", header: "Server", valor: headers["server"], severidade: "LOW",
        descricao: `Servidor exposto: "${headers["server"]}" — atacante sabe qual software atacar` });
    }
    if (headers["x-powered-by"]) {
      problemas.push({ tipo: "TECHNOLOGY_EXPOSURE", header: "X-Powered-By", valor: headers["x-powered-by"],
        severidade: "LOW", descricao: `Tecnologia exposta: "${headers["x-powered-by"]}"` });
    }
    const cookies = headers["set-cookie"];
    if (cookies) {
      const cookieStr = Array.isArray(cookies) ? cookies.join("; ") : cookies;
      if (!cookieStr.toLowerCase().includes("httponly")) {
        problemas.push({ tipo: "INSECURE_COOKIE", header: "Set-Cookie", severidade: "HIGH",
          descricao: "Cookie sem flag HttpOnly — JavaScript pode roubar o cookie" });
      }
      if (!cookieStr.toLowerCase().includes("secure") && url.startsWith("https")) {
        problemas.push({ tipo: "INSECURE_COOKIE", header: "Set-Cookie", severidade: "MEDIUM",
          descricao: "Cookie sem flag Secure — pode ser enviado em HTTP inseguro" });
      }
    }

    const score = calcularScore(problemas);
    return {
      target: url,
      status: resposta.status,
      tempo_resposta_ms: tempoResposta,
      total_problemas: problemas.length,
      score_seguranca: score,
      nivel_risco: calcularNivelRisco(score),
      headers_recebidos: Object.keys(headers).length,
      problemas,
      issues: problemas.map((p) => p.descricao),
    };

  } catch (erro) {
    if (erro.code === "ECONNREFUSED") throw new Error("Conexão recusada — servidor offline");
    if (erro.code === "ENOTFOUND")    throw new Error("Domínio não encontrado — verifique a URL");
    if (erro.code === "ETIMEDOUT" || erro.message.includes("timeout")) {
      throw new Error("Timeout — servidor demorou mais de 5 segundos");
    }
    throw new Error(`Erro ao acessar URL: ${erro.message}`);
  }
}

module.exports = { escanear };
