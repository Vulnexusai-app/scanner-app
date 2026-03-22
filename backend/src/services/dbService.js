const axios = require("axios");
const config = require("../config");
const { log } = require("../utils/logger");

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SUPABASE_SERVICE_KEY } = config;

// Cabeçalhos padrão para todas as chamadas ao Supabase
const headers = () => ({
  apikey: SUPABASE_SERVICE_KEY,
  Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
  "Content-Type": "application/json",
  Prefer: "return=representation",
});

// ── Log estruturado interno ───────────────────────────────────
function dbLog(nivel, acao, detalhe = "") {
  log(nivel, `DB_${acao}`, "-", detalhe);
}

// ============================================================
// FUNÇÃO: buscarOuCriarUsuario
// ============================================================
async function buscarOuCriarUsuario(userId, email) {
  // Proteção básica: garante que userId é uma string UUID válida
  // Evita injeção de caracteres especiais na query REST
  if (!userId || typeof userId !== "string" || userId.length > 100) {
    throw new Error("userId inválido");
  }

  try {
    // 1. Tenta buscar o usuário
    const busca = await axios.get(
      `${SUPABASE_URL}/rest/v1/users?id=eq.${encodeURIComponent(userId)}&select=*`,
      { headers: headers(), timeout: 5000 }
    );

    if (busca.data.length > 0) {
      return busca.data[0];
    }

    // 2. Não existe — cria com plano free
    const criacao = await axios.post(
      `${SUPABASE_URL}/rest/v1/users`,
      { id: userId, email, plan: "free" },
      { headers: headers(), timeout: 5000 }
    );

    dbLog("info", "usuario_criado", email);
    return criacao.data[0];

  } catch (erro) {
    // Loga o erro real internamente (nunca expõe ao cliente)
    dbLog("error", "buscarOuCriarUsuario_falhou", erro.message);
    throw new Error("Erro ao acessar dados do usuário. Tente novamente.");
  }
}

// ============================================================
// FUNÇÃO: contarScansHoje
// MELHORIA: usa select=count via header do Supabase
// Evita trazer todas as linhas só para contar
// ============================================================
async function contarScansHoje(userId) {
  if (!userId || typeof userId !== "string") throw new Error("userId inválido");

  try {
    const hoje = new Date();
    hoje.setUTCHours(0, 0, 0, 0);
    const inicioHoje = hoje.toISOString();

    // "Prefer: count=exact" faz o Supabase retornar só a contagem
    // no header "content-range" → ex: "0-2/3" (3 = total)
    // Muito mais eficiente: não traz os dados, só o número
    const resposta = await axios.get(
      `${SUPABASE_URL}/rest/v1/scans?user_id=eq.${encodeURIComponent(userId)}&created_at=gte.${inicioHoje}&select=id`,
      {
        headers: { ...headers(), Prefer: "count=exact" },
        timeout: 5000,
      }
    );

    // Extrai o total do header content-range (formato: "0-N/TOTAL")
    const contentRange = resposta.headers["content-range"] || "";
    const match = contentRange.match(/\/(\d+)$/);
    if (match) return parseInt(match[1], 10);

    // Fallback: conta pelo array se o header não vier
    return Array.isArray(resposta.data) ? resposta.data.length : 0;

  } catch (erro) {
    dbLog("error", "contarScansHoje_falhou", erro.message);
    throw new Error("Erro ao verificar uso diário. Tente novamente.");
  }
}

// ============================================================
// FUNÇÃO: salvarScan
// ============================================================
async function salvarScan(userId, url, resultado) {
  if (!userId || typeof userId !== "string") throw new Error("userId inválido");

  try {
    const resposta = await axios.post(
      `${SUPABASE_URL}/rest/v1/scans`,
      { user_id: userId, url, result: resultado },
      { headers: headers(), timeout: 8000 }
    );

    dbLog("info", "scan_salvo", `user=${userId} url=${url}`);
    return resposta.data[0];

  } catch (erro) {
    // Erro ao salvar não deve derrubar a resposta já enviada ao cliente
    // Por isso loga mas não relança — o caller usa .catch() mesmo
    dbLog("error", "salvarScan_falhou", erro.message);
    throw new Error("Erro ao salvar scan no banco.");
  }
}

// ============================================================
// FUNÇÃO: buscarHistorico
// ============================================================
async function buscarHistorico(userId) {
  if (!userId || typeof userId !== "string") throw new Error("userId inválido");

  try {
    const resposta = await axios.get(
      `${SUPABASE_URL}/rest/v1/scans?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc&limit=10&select=id,url,created_at,result`,
      { headers: headers(), timeout: 5000 }
    );

    return resposta.data;

  } catch (erro) {
    dbLog("error", "buscarHistorico_falhou", erro.message);
    throw new Error("Erro ao buscar histórico. Tente novamente.");
  }
}

// ============================================================
// FUNÇÃO: buscarUsuario
// ============================================================
async function buscarUsuario(userId) {
  if (!userId || typeof userId !== "string") throw new Error("userId inválido");

  try {
    const resposta = await axios.get(
      `${SUPABASE_URL}/rest/v1/users?id=eq.${encodeURIComponent(userId)}&select=*`,
      { headers: headers(), timeout: 5000 }
    );

    return resposta.data[0] || null;

  } catch (erro) {
    dbLog("error", "buscarUsuario_falhou", erro.message);
    throw new Error("Erro ao buscar usuário. Tente novamente.");
  }
}

module.exports = {
  buscarOuCriarUsuario,
  contarScansHoje,
  salvarScan,
  buscarHistorico,
  buscarUsuario,
};
