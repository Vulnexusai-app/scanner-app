/**
 * VulnexusAI Scanner Engine — v4.0 (Professional)
 * OWASP Top-10 aligned, test-env aware, retry-enabled
 */
const axios = require("axios");

// ─── CONSTANTES ────────────────────────────────────────────────────────────────
const DOMINIOS_TESTE = ["httpbin.org", "reqres.in", "jsonplaceholder.typicode.com",
  "httpbin", "reqres", "sandbox", "mockapi", "fakeapi", "test.", ".test",
  "staging.", ".staging", "dev.", ".dev", "example.com", "example.org"];

const CABECALHOS_SEGURANCA = [
  { nome: "x-frame-options",          severidade: "MEDIUM", descricao: "X-Frame-Options ausente — vulnerável a Clickjacking" },
  { nome: "content-security-policy",  severidade: "HIGH",   descricao: "Content-Security-Policy ausente — vulnerável a XSS" },
  { nome: "x-content-type-options",   severidade: "LOW",    descricao: "X-Content-Type-Options ausente — MIME sniffing possível" },
  { nome: "referrer-policy",          severidade: "LOW",    descricao: "Referrer-Policy ausente — vazamento de URL de referência" },
  { nome: "permissions-policy",       severidade: "LOW",    descricao: "Permissions-Policy ausente — APIs do browser expostas" },
];
// HSTS só conta em HTTPS
const HSTS = { nome: "strict-transport-security", severidade: "MEDIUM", descricao: "HSTS ausente — usuários podem ser redirecionados para HTTP" };

const PENALIDADES = { HIGH: 25, MEDIUM: 12, LOW: 5 };
const BONUS_HTTPS   = 5;

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function isAmbienteTeste(url) {
  const u = url.toLowerCase();
  return DOMINIOS_TESTE.some(d => u.includes(d));
}

function calcularScore(problemas, url, status) {
  let score = 100;
  for (const p of problemas) score -= PENALIDADES[p.severidade] || 5;
  if (url.startsWith("https://")) score += BONUS_HTTPS;
  if (status >= 500) score -= 20;
  else if (status >= 400) score -= 8;
  return Math.max(0, Math.min(100, score));
}

function calcularNivelRisco(score, ambienteTeste) {
  if (ambienteTeste) return "INFO";
  if (score >= 80) return "LOW";
  if (score >= 50) return "MEDIUM";
  return "HIGH";
}

// ─── AXIOS COM RETRY ──────────────────────────────────────────────────────────
async function fetchComRetry(url, tentativas = 2) {
  const opcoes = {
    timeout: 8000,
    validateStatus: () => true,
    headers: {
      "User-Agent": "VulnexusAI-Scanner/4.0",
      "Accept": "application/json, text/html, */*",
    },
    maxRedirects: 5,
    decompress: true,
  };

  let ultimoErro;
  for (let i = 0; i < tentativas; i++) {
    try {
      return await axios.get(url, opcoes);
    } catch (err) {
      ultimoErro = err;
      if (err.code === "ENOTFOUND" || err.code === "ECONNREFUSED") break; // sem retry para DNS/refused
      if (i < tentativas - 1) await new Promise(r => setTimeout(r, 1500));
    }
  }
  throw ultimoErro;
}

// ─── CHECKS INDIVIDUAIS ────────────────────────────────────────────────────────
function checkHeaders(headers, url) {
  const problemas = [];

  // Headers obrigatórios
  for (const h of CABECALHOS_SEGURANCA) {
    if (!headers[h.nome]) {
      problemas.push({ tipo: "MISSING_SECURITY_HEADER", header: h.nome, severidade: h.severidade,
        descricao: h.descricao, owasp: "A05:2021 – Security Misconfiguration" });
    }
  }
  if (!headers[HSTS.nome] && url.startsWith("https")) {
    problemas.push({ tipo: "MISSING_SECURITY_HEADER", header: HSTS.nome, severidade: HSTS.severidade,
      descricao: HSTS.descricao, owasp: "A05:2021 – Security Misconfiguration" });
  }

  // CORS aberto
  const cors = headers["access-control-allow-origin"];
  if (cors === "*") {
    problemas.push({ tipo: "CORS_MISCONFIGURATION", header: "Access-Control-Allow-Origin", severidade: "HIGH",
      descricao: "CORS wildcard (*) — qualquer origem pode fazer requisições autenticadas",
      owasp: "A01:2021 – Broken Access Control" });
  }

  // Exposição de stack
  const server = headers["server"];
  if (server) {
    problemas.push({ tipo: "SERVER_FINGERPRINT", header: "Server", valor: server, severidade: "LOW",
      descricao: `Stack exposta: "${server}" — atacante identifica versões vulneráveis`,
      owasp: "A05:2021 – Security Misconfiguration" });
  }
  const xpowered = headers["x-powered-by"];
  if (xpowered) {
    problemas.push({ tipo: "FRAMEWORK_FINGERPRINT", header: "X-Powered-By", valor: xpowered, severidade: "LOW",
      descricao: `Framework exposto: "${xpowered}"`, owasp: "A05:2021 – Security Misconfiguration" });
  }

  // Cookies inseguros
  const cookies = headers["set-cookie"];
  if (cookies) {
    const s = Array.isArray(cookies) ? cookies.join("; ") : cookies;
    if (!s.toLowerCase().includes("httponly")) {
      problemas.push({ tipo: "INSECURE_COOKIE", header: "Set-Cookie", severidade: "HIGH",
        descricao: "Cookie sem HttpOnly — JavaScript pode roubar sessão via XSS",
        owasp: "A07:2021 – Identification and Authentication Failures" });
    }
    if (!s.toLowerCase().includes("secure") && url.startsWith("https")) {
      problemas.push({ tipo: "INSECURE_COOKIE", header: "Set-Cookie", severidade: "MEDIUM",
        descricao: "Cookie sem Secure — pode ser transmitido em HTTP",
        owasp: "A07:2021 – Identification and Authentication Failures" });
    }
    if (!s.toLowerCase().includes("samesite")) {
      problemas.push({ tipo: "INSECURE_COOKIE", header: "Set-Cookie", severidade: "MEDIUM",
        descricao: "Cookie sem SameSite — vulnerável a CSRF",
        owasp: "A01:2021 – Broken Access Control" });
    }
  }

  return problemas;
}

function checkStatus(status, url, ambienteTeste) {
  const problemas = [];
  if (ambienteTeste) return problemas; // Não gera alertas de status para ambientes de teste

  if (status >= 500) {
    problemas.push({ tipo: "SERVER_ERROR", severidade: "HIGH",
      descricao: `Status ${status} — erro interno do servidor exposto publicamente, pode vazar stack traces`,
      owasp: "A09:2021 – Security Logging and Monitoring Failures" });
  } else if (status === 403) {
    problemas.push({ tipo: "ACCESS_CONTROL", severidade: "MEDIUM",
      descricao: "Status 403 — recurso existe mas acesso negado. Verifique se a negação é consistente",
      owasp: "A01:2021 – Broken Access Control" });
  } else if (status === 401) {
    problemas.push({ tipo: "AUTH_REQUIRED", severidade: "LOW",
      descricao: "Status 401 — autenticação necessária. Confirme que o endpoint não retorna dados sensíveis sem auth",
      owasp: "A07:2021 – Identification and Authentication Failures" });
  }
  return problemas;
}

function checkBody(body, status) {
  const problemas = [];
  if (!body) return problemas;

  const texto = typeof body === "string" ? body : JSON.stringify(body);
  const truncado = texto.slice(0, 3000).toLowerCase();

  // Stack trace / erro detalhado exposto
  const padroesSensíveis = [
    { re: /stack trace|stacktrace|at [\w<>$.]+\([\w/.]+:\d+:\d+\)/, msg: "Stack trace exposto na resposta — vaza informações internas" },
    { re: /exception|unhandled.+error|internal server error/,        msg: "Mensagem de erro interna exposta — vaza estrutura do servidor" },
    { re: /sql syntax|mysql_fetch|sqlite|ora-\d{5}|pg_query/,        msg: "Erro de SQL visível na resposta — ataque de SQL Injection facilitado" },
    { re: /password|passwd|secret|api_key|apikey|token.*=["'][^"']+["']/,
      msg: "Dado sensível (senha/chave) encontrado na resposta — exposição de credenciais" },
    { re: /private.key|-----begin (rsa|ec|private|certificate)/,
      msg: "Chave privada/certificado exposto na resposta pública" },
  ];

  for (const { re, msg } of padroesSensíveis) {
    if (re.test(truncado)) {
      problemas.push({ tipo: "SENSITIVE_DATA_EXPOSURE", severidade: "HIGH",
        descricao: msg, owasp: "A02:2021 – Cryptographic Failures" });
      break; // Um por categoria suficiente para não inflar score
    }
  }

  // Resposta muito grande em erro pode indicar dump
  if (status >= 400 && texto.length > 10000) {
    problemas.push({ tipo: "VERBOSE_ERROR_RESPONSE", severidade: "MEDIUM",
      descricao: "Resposta de erro muito grande (>10KB) — possível dump de dados internos",
      owasp: "A09:2021 – Security Logging and Monitoring Failures" });
  }

  return problemas;
}

function checkRateLimit(headers) {
  const problemas = [];
  const indicadores = ["x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit", "retry-after"];
  const temRateLimit = indicadores.some(h => headers[h]);
  if (!temRateLimit) {
    problemas.push({ tipo: "NO_RATE_LIMITING", severidade: "MEDIUM",
      descricao: "Nenhum header de rate-limit detectado — API possivelmente sem proteção contra brute-force",
      owasp: "A04:2021 – Insecure Design" });
  }
  return problemas;
}

// ─── ENGINE PRINCIPAL ─────────────────────────────────────────────────────────
async function escanear(url) {
  const inicio = Date.now();
  const ambienteTeste = isAmbienteTeste(url);

  let resposta;
  try {
    resposta = await fetchComRetry(url);
  } catch (erro) {
    if (erro.code === "ECONNREFUSED") throw new Error("Conexão recusada — servidor offline ou porta fechada");
    if (erro.code === "ENOTFOUND")    throw new Error("Domínio não encontrado — verifique a URL");
    if (erro.code === "ETIMEDOUT" || (erro.message || "").includes("timeout"))
      throw new Error("Timeout — servidor não respondeu em 8 segundos (tentativas: 2)");
    throw new Error(`Erro ao acessar a URL: ${erro.message}`);
  }

  const tempoResposta = Date.now() - inicio;
  const { status, headers, data: body } = resposta;

  // Coleta de checks
  const problemas = [
    ...checkStatus(status, url, ambienteTeste),
    ...checkHeaders(headers, url),
    ...checkBody(body, status),
    ...checkRateLimit(headers),
  ];

  // Score final
  const score = calcularScore(problemas, url, status);
  const nivelRisco = calcularNivelRisco(score, ambienteTeste);

  // Resumo dos headers recebidos (apenas nomes, para o prompt da IA)
  const headersRecebidos = Object.keys(headers);

  // Body snippet para IA (limitado a 500 chars)
  const bodySnippet = (() => {
    const txt = typeof body === "string" ? body : JSON.stringify(body);
    return txt ? txt.slice(0, 500) : "";
  })();

  return {
    // Identificação
    target:           url,
    ambiente_teste:   ambienteTeste,
    ambiente_nota:    ambienteTeste ? "Domínio de teste/sandbox detectado — resultados têm caráter informativo" : null,

    // HTTP
    status,
    tempo_resposta_ms: tempoResposta,

    // Segurança
    score_seguranca:  score,
    nivel_risco:      nivelRisco,
    total_problemas:  problemas.length,
    problemas,

    // Para IA
    issues:           problemas.map(p => `[${p.severidade}] ${p.descricao} (${p.owasp || "N/A"})`),
    headers_recebidos: headersRecebidos,
    body_snippet:     bodySnippet,

    // Sumarizado
    alto_risco:   problemas.filter(p => p.severidade === "HIGH").length,
    medio_risco:  problemas.filter(p => p.severidade === "MEDIUM").length,
    baixo_risco:  problemas.filter(p => p.severidade === "LOW").length,
  };
}

module.exports = { escanear };
