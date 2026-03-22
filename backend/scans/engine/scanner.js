/**
 * VulnexusAI Extreme Security Engine — v5.0 (Enterprise)
 * Segurança Ofensiva & Defensiva de Elite
 */
const axios = require("axios");
const dns = require("dns").promises;

// ─── CONFIGURAÇÕES E CONSTANTES ───────────────────────────────────────────────
const DOMINIOS_TESTE = ["httpbin.org", "reqres.in", "jsonplaceholder.typicode.com", "sandbox", "mock", "fake", "test.", ".test", "example.com"];
const ENDPOINTS_ENUMERACAO = ["/admin", "/login", "/debug", "/config", "/api/v1", "/.env", "/phpinfo.php", "/wp-admin"];
const PARAMETROS_FUZZING = ["?debug=true", "?test=1", "?admin=true", "?dev=1"];

const CABECALHOS_SEGURANCA = [
  { nome: "x-frame-options",          sev: "MEDIUM", desc: "X-Frame-Options ausente — vulnerável a Clickjacking" },
  { nome: "content-security-policy",  sev: "HIGH",   desc: "Content-Security-Policy ausente — vulnerável a XSS" },
  { nome: "x-content-type-options",   sev: "LOW",    desc: "X-Content-Type-Options ausente — MIME sniffing possível" },
  { nome: "strict-transport-security", sev: "MEDIUM", desc: "HSTS ausente — risco de downgrade para HTTP" },
  { nome: "access-control-allow-origin", sev: "HIGH",  desc: "CORS aberto (*) — qualquer origem pode ler dados" },
];

const PADROES_SEGREDOS = [
  { id: "JWT_TOKEN",     re: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/, sev: "CRITICAL", desc: "Token JWT detectado na resposta" },
  { id: "BEARER_TOKEN",  re: /Bearer\s+[A-Za-z0-9-_=.]+/, sev: "CRITICAL", desc: "Bearer Token exposto" },
  { id: "AWS_KEY",       re: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/, sev: "CRITICAL", desc: "Chave AWS exposta" },
  { id: "GOOGLE_KEY",    re: /AIza[0-9A-Za-z\-_]{35}/, sev: "CRITICAL", desc: "Chave Google API detectada" },
  { id: "GENERIC_KEY",   re: /(?:key|secret|passwd|password|token)["']\s*[:=]\s*["']([^"']{10,})["']/i, sev: "CRITICAL", desc: "Credencial ou Chave de API detectada" },
  { id: "PRIVATE_KEY",   re: /-----BEGIN (?:RSA|EC|PRIVATE|OPENSSH) KEY-----/, sev: "CRITICAL", desc: "Chave Privada exposta" }
];

// ─── AUXILIARES ───────────────────────────────────────────────────────────────
function getBaseUrl(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}`; } catch (e) { return url; }
}

function isAmbienteTeste(url) {
  const u = url.toLowerCase();
  return DOMINIOS_TESTE.some(d => u.includes(d));
}

function isPrivateIP(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.|::1|fe80:)/.test(ip);
}

// ─── LÓGICA DE SCORE ──────────────────────────────────────────────────────────
function calcularScoreEnterprise(vulns, status, url, ambienteTeste) {
  let score = 100;
  vulns.forEach(v => {
    if (v.severidade === "CRITICAL") score -= 40;
    else if (v.severidade === "HIGH") score -= 25;
    else if (v.severidade === "MEDIUM") score -= 10;
    else if (v.severidade === "LOW") score -= 3;
  });

  if (status >= 500) score -= 20;
  if (!url.startsWith("https://")) score -= 10;
  
  // Penalidade adicional por múltiplas falhas críticas
  const nCriticas = vulns.filter(v => v.severidade === "CRITICAL" || v.severidade === "HIGH").length;
  if (nCriticas > 2) score -= 15;

  score = Math.max(0, Math.min(100, score));

  let nivel = "SEGURO";
  if (score < 20) nivel = "CRÍTICO";
  else if (score < 50) nivel = "VULNERÁVEL";
  else if (score < 70) nivel = "ATENÇÃO";
  else if (score < 90) nivel = "BOM";

  return { score, nivel };
}

// ─── REQUISIÇÕES ──────────────────────────────────────────────────────────────
async function request(url, timeout = 7000) {
  return axios.get(url, {
    timeout,
    validateStatus: () => true,
    headers: { "User-Agent": "VulnexusAI-Extreme/5.0", "Accept": "*/*" },
    maxRedirects: 3
  });
}

// ─── CHECKS ───────────────────────────────────────────────────────────────────
function analisarHeaders(headers, url) {
  const v = [];
  CABECALHOS_SEGURANCA.forEach(h => {
    const val = headers[h.nome];
    if (!val) v.push({ tipo: "MISSING_HEADER", header: h.nome, severidade: h.sev, descricao: h.desc });
    else if (h.nome === "content-security-policy" && (val.includes("'unsafe-inline'") || val.includes("*")))
      v.push({ tipo: "WEAK_CSP", header: "CSP", severidade: "MEDIUM", descricao: "CSP Fraco (unsafe-inline ou wildcard detectado)" });
    else if (h.nome === "access-control-allow-origin" && val === "*")
      v.push({ tipo: "OPEN_CORS", header: "CORS", severidade: "HIGH", descricao: "CORS Aberto (Access-Control-Allow-Origin: *)" });
  });

  if (headers["server"]) v.push({ tipo: "FINGERPRINT", header: "Server", severidade: "LOW", descricao: `Banner do servidor exposto: ${headers["server"]}` });
  
  const cookie = headers["set-cookie"];
  if (cookie) {
    const s = Array.isArray(cookie) ? cookie.join(" ") : cookie;
    if (!s.toLowerCase().includes("httponly")) v.push({ tipo: "INSECURE_COOKIE", severidade: "MEDIUM", descricao: "Cookie sem flag HttpOnly" });
  }

  return v;
}

function analisarCorpo(body) {
  const v = [];
  if (!body) return v;
  const texto = typeof body === "string" ? body : JSON.stringify(body);
  
  PADROES_SEGREDOS.forEach(p => {
    if (p.re.test(texto)) v.push({ tipo: "SENSITIVE_DATA", severidade: p.sev, descricao: p.desc });
  });

  if (texto.includes("stack trace") || texto.includes("at line") || texto.includes("SQL syntax"))
    v.push({ tipo: "SERVER_ERROR_DETAIL", severidade: "HIGH", descricao: "Stack trace ou erro detalhado exposto no corpo" });

  return v;
}

function correlacionar(vulns) {
  const c = [];
  const tipos = vulns.map(v => v.tipo);
  if (tipos.includes("WEAK_CSP") && tipos.includes("OPEN_CORS"))
    c.push("Combinação Crítica: CSP Fraco + CORS Aberto facilita significativamente ataques XSS e roubo de dados.");
  if (tipos.includes("FINGERPRINT") && tipos.includes("SERVER_ERROR_DETAIL"))
    c.push("Risco Elevado: Banner de servidor exposto combinado com erros detalhados facilita a busca por exploits específicos.");
  return c;
}

// ─── OFENSIVO ──────────────────────────────────────────────────────────────────
async function fuzzing(baseUrl) {
  const achados = [];
  for (const param of PARAMETROS_FUZZING) {
    try {
      const res = await request(baseUrl + param, 4000);
      if (res.status === 200 && res.data && JSON.stringify(res.data).length > 200) {
        achados.push({ tipo: "FUZZING_DISCOVERY", severidade: "MEDIUM", descricao: `Comportamento anômalo detectado com parâmetro: ${param}` });
      }
    } catch (e) {}
  }
  return achados;
}

async function enumerar(baseUrl) {
  const achados = [];
  const tests = ENDPOINTS_ENUMERACAO.map(async (path) => {
    try {
      const res = await request(baseUrl + path, 3000);
      if ([200, 403, 401].includes(res.status)) {
        achados.push({ tipo: "ENDPOINT_ENUMERATION", severidade: "LOW", descricao: `Possível superfície de ataque encontrada: ${path} (Status ${res.status})` });
      }
    } catch (e) {}
  });
  await Promise.all(tests.slice(0, 5)); // Limitar concorrência
  return achados;
}

// ─── PRINCIPAL ────────────────────────────────────────────────────────────────
async function escanear(url) {
  const inicio = Date.now();
  const ambienteTeste = isAmbienteTeste(url);
  const baseUrl = getBaseUrl(url);

  console.log(`[Elite Scanner] Alvo: ${url} | Ambiente: ${ambienteTeste ? 'TESTE' : 'REAL'}`);

  // 1. Requisição Principal
  let resposta;
  try {
    resposta = await request(url);
  } catch (e) {
    throw new Error(`Falha crítica de conexão: ${e.message}`);
  }

  // 2. Segurança do Scanner (SSRF)
  let ssrfVuln = null;
  try {
    const host = new URL(url).hostname;
    const { address } = await dns.lookup(host);
    if (isPrivateIP(address) && !ambienteTeste) {
       ssrfVuln = { tipo: "SSRF_ATEMPT", severidade: "CRITICAL", descricao: "Host resolve para IP privado — Bloqueado por proteção SSRF" };
    }
  } catch (e) {}

  // 3. Ofensivo (em paralelo)
  const [fuzzVulns, enumVulns] = await Promise.all([
    fuzzing(baseUrl),
    enumerar(baseUrl)
  ]);

  // 4. Consolidação
  const rawVulns = [
    ...analisarHeaders(resposta.headers, url),
    ...analisarCorpo(resposta.data),
    ...fuzzVulns,
    ...enumVulns
  ];
  if (ssrfVuln) rawVulns.push(ssrfVuln);

  // Ajuste por Ambiente de Teste
  if (ambienteTeste) {
    rawVulns.forEach(v => {
      if (v.severidade === "CRITICAL") v.severidade = "HIGH";
      else if (v.severidade === "HIGH") v.severidade = "MEDIUM";
      else v.severidade = "LOW";
    });
  }

  const { score, nivel } = calcularScoreEnterprise(rawVulns, resposta.status, url, ambienteTeste);
  const correlacoes = correlacionar(rawVulns);

  // 5. Agrupamento Obrigatório
  const vulns = {
    criticas: rawVulns.filter(v => ["CRITICAL", "HIGH"].includes(v.severidade)),
    moderadas: rawVulns.filter(v => v.severidade === "MEDIUM"),
    baixas: rawVulns.filter(v => v.severidade === "LOW"),
    informativas: []
  };

  if (ambienteTeste) vulns.informativas.push({ tipo: "CONTEXT", severidade: "INFO", descricao: "Ambiente de teste detectado — resultados não refletem ambiente real" });

  return {
    url,
    status: resposta.status,
    tempo_ms: Date.now() - inicio,
    contexto: ambienteTeste ? "Sandbox/Teste" : "Produção",
    score,
    nivel,
    resumo: {
      criticas: vulns.criticas.length,
      moderadas: vulns.moderadas.length,
      baixas: vulns.baixas.length,
      score,
      nivel
    },
    vulnerabilidades: vulns,
    correlacoes,
    // Snippets para IA
    body_snippet: typeof resposta.data === "string" ? resposta.data.slice(0, 500) : JSON.stringify(resposta.data).slice(0, 500),
    headers_recebidos: Object.keys(resposta.headers)
  };
}

module.exports = { escanear };
