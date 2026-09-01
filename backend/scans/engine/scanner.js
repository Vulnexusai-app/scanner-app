/**
 * VulnexusAI Extreme Security Engine — v5.0 (Enterprise)
 * Segurança Ofensiva & Defensiva de Elite — Modularizado
 */
const axios = require("axios");
const http = require("node:http");
const https = require("node:https");
const { validarHostPublico, isIPProibido, SSRFError } = require("../../src/utils/ssrf");

// ─── IMPORTAÇÃO DOS MÓDULOS ───────────────────────────────────────────────────
// Módulos Extraídos
const { analisarHeaders } = require("../modules/headers");
const { analisarCORS } = require("../modules/cors");
const { analisarCorpo: analisarSecrets } = require("../modules/secrets");
const { analisarSSRF } = require("../modules/ssrf");
const { runFuzzing } = require("../modules/fuzzing");
const { runEnumeration } = require("../modules/enumeration");

// Módulos Novos
const { testarSQLi } = require("../modules/sqli");
const { testarXSS } = require("../modules/xss");
const { testarJWT } = require("../modules/jwt");
const { testarBOLA } = require("../modules/bola");
const { testarGraphQL } = require("../modules/graphql");
const { testarRateLimit } = require("../modules/rateLimit");

// ─── CONFIGURAÇÕES E CONSTANTES ───────────────────────────────────────────────
const DOMINIOS_TESTE = ["httpbin.org", "reqres.in", "jsonplaceholder.typicode.com", "sandbox", "mock", "fake", "test.", ".test", "example.com"];

// ─── AUXILIARES ───────────────────────────────────────────────────────────────
function getBaseUrl(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}`; } catch (e) { return url; }
}

function isAmbienteTeste(url) {
  const u = url.toLowerCase();
  return DOMINIOS_TESTE.some(d => u.includes(d));
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
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 3;

/**
 * Cria um agente HTTP/HTTPS com um `lookup` customizado que revalida o DNS
 * na hora da conexão e NUNCA conecta a um IP privado/loopback/link-local
 * (proteção contra DNS rebinding). Lança SSRFError se resolver para interno.
 */
function criarAgenteSeguro() {
  const lookupSeguro = async (hostname, options, callback) => {
    try {
      const lista = await require("node:dns/promises").lookup(hostname, { all: true, verbatim: true });
      const enderecos = Array.isArray(lista) ? lista : [];
      // Revalida cada IP no momento da conexão (novo resolve: cobre rebinding).
      for (const item of enderecos) {
        if (isIPProibido(item.address)) {
          return callback(new SSRFError(`Resolução para IP interno (${item.address}) bloqueada (SSRF)`));
        }
      }
      if (options && options.all) return callback(null, enderecos);
      const escolhido = enderecos.find(i => i.family === 4) || enderecos[0];
      return callback(null, escolhido ? escolhido.address : null, escolhido ? escolhido.family : null);
    } catch (e) {
      return callback(e instanceof Error ? e : new Error(String(e)));
    }
  };

  return {
    http: new http.Agent({ lookup: lookupSeguro, keepAlive: false }),
    https: new https.Agent({ lookup: lookupSeguro, keepAlive: false }),
  };
}

/**
 * Valida a URL antes de qualquer requisição: resolve o hostname e confirma que
 * ele aponta apenas para endereços públicos (ORIGINAL + cada redirect).
 */
async function request(url, timeout = 7000, method = "GET", data = null) {
  let alvo = url;
  for (let passo = 0; passo <= MAX_REDIRECTS; passo++) {
    const config = {
      method,
      url: alvo,
      timeout,
      validateStatus: () => true,
      headers: { "User-Agent": "VulnexusAI-Extreme/5.0", "Accept": "*/*" },
      maxRedirects: 0, // redirecionamentos tratados manualmente aqui embaixo
      proxy: false,
    };
    if (data) config.data = data;

    // Pre-valida via DNS o hostname do alvo (original e a cada redirect).
    const u = new URL(alvo);
    await validarHostPublico(u.hostname);

    // Conecta com agente que revalida a resolução no momento da conexão.
    const agentes = criarAgenteSeguro();
    config.httpAgent = agentes.http;
    config.httpsAgent = agentes.https;

    const resposta = await axios(config);

    // É redirect e queremos segui-lo? Revalidamos o Location antes.
    if (REDIRECT_STATUS.has(resposta.status) && resposta.headers.location) {
      let prox;
      try {
        prox = new URL(resposta.headers.location, alvo).toString();
      } catch {
        throw new SSRFError("Location inválido em redirecionamento");
      }
      const proxProtocol = new URL(prox).protocol;
      if (!["http:", "https:"].includes(proxProtocol)) {
        throw new SSRFError("Redirecionamento para protocolo não permitido");
      }
      // A próxima iteração revalida via DNS o novo hostname.
      alvo = prox;
      if (passo === MAX_REDIRECTS) {
        throw new SSRFError("Número máximo de redirecionamentos excedido");
      }
      continue;
    }

    return resposta;
  }
  throw new SSRFError("Redirecionamento em loop ou inválido");
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

// ─── PRINCIPAL ────────────────────────────────────────────────────────────────
async function escanear(url) {
  const inicio = Date.now();
  const ambienteTeste = isAmbienteTeste(url);
  const baseUrl = getBaseUrl(url);

  // 1. Requisição Principal
  let resposta;
  try {
    resposta = await request(url);
  } catch (e) {
    throw new Error(`Falha crítica de conexão: ${e.message}`);
  }

  // 2. Orquestração Modular via Promise.all
  const [
    headerVulns,
    corsVulns,
    secretVulns,
    ssrfVulns,
    fuzzVulns,
    enumVulns,
    sqliVulns,
    xssVulns,
    jwtVulns,
    bolaVulns,
    gqlVulns,
    rateVulns
  ] = await Promise.all([
    analisarHeaders(resposta.headers, url),
    analisarCORS(resposta.headers),
    analisarSecrets(resposta.data),
    analisarSSRF(url, ambienteTeste),
    runFuzzing(baseUrl, request),
    runEnumeration(baseUrl, request),
    testarSQLi(baseUrl, [url]), // Adaptado para array
    testarXSS(baseUrl, [url]), // Adaptado para array
    testarJWT(url, resposta.data),
    testarBOLA(url, [url]), // Adaptado para array
    testarGraphQL(baseUrl),
    testarRateLimit(url, request)
  ]);

  // 3. Consolidação
  const rawVulns = [
    ...headerVulns,
    ...corsVulns,
    ...secretVulns,
    ...ssrfVulns,
    ...fuzzVulns,
    ...enumVulns,
    ...sqliVulns,
    ...xssVulns,
    ...jwtVulns,
    ...bolaVulns,
    ...gqlVulns,
    ...rateVulns
  ];

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

  // 4. Agrupamento Obrigatório para o Frontend
  const vulns = {
    criticas: rawVulns.filter(v => ["CRITICAL", "HIGH"].includes(v.severidade)),
    moderadas: rawVulns.filter(v => v.severidade === "MEDIUM"),
    baixas: rawVulns.filter(v => v.severidade === "LOW"),
    informativas: []
  };

  if (ambienteTeste) vulns.informativas.push({ tipo: "CONTEXT", severidade: "INFO", descricao: "Ambiente de teste detectado — resultados ajustados" });

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
    body_snippet: typeof resposta.data === "string" ? resposta.data.slice(0, 500) : JSON.stringify(resposta.data).slice(0, 500),
    headers_recebidos: Object.keys(resposta.headers)
  };
}

module.exports = { escanear };
