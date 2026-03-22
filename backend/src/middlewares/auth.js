const axios = require("axios");
const config = require("../config");

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SUPABASE_SERVICE_KEY } = config;

// ============================================================
// FUNÇÃO: verificarToken
// Recebe o token JWT do usuário e verifica com o Supabase
// Retorna os dados do usuário se válido, ou lança erro
// ============================================================
async function verificarToken(token) {
  if (!token) throw new Error("Token não fornecido");
  if (!SUPABASE_URL) throw new Error("SUPABASE_URL não configurada");

  try {
    // Chama a API do Supabase para verificar quem é esse token
    const resposta = await axios.get(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        Authorization: `Bearer ${token}`,
        apikey: SUPABASE_SERVICE_KEY,
      },
      timeout: 5000,
    });

    return resposta.data; // { id, email, ... }
  } catch (erro) {
    if (erro.response?.status === 401) {
      throw new Error("Token inválido ou expirado — faça login novamente");
    }
    throw new Error("Erro ao verificar autenticação");
  }
}

// ============================================================
// MIDDLEWARE: autenticar
// Usado nas rotas protegidas: app.post("/scan", autenticar, ...)
// Extrai o token do header Authorization e coloca o user no req
// ============================================================
async function autenticar(req, res, next) {
  // Pega o header: "Authorization: Bearer SEU_TOKEN"
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      erro: "Não autorizado",
      dica: "Envie o header: Authorization: Bearer SEU_TOKEN",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const usuario = await verificarToken(token);
    // Coloca o usuário na requisição para usar nas rotas
    req.usuario = usuario;
    next(); // continua para a rota
  } catch (erro) {
    return res.status(401).json({ erro: erro.message });
  }
}

module.exports = { autenticar, verificarToken };
