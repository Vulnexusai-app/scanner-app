const express = require("express");
const axios = require("axios");
const config = require("../config");

const router = express.Router();
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config;

// Chave anon separada para operações de auth em nome do usuário
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || SUPABASE_SERVICE_ROLE_KEY;

// POST /api/auth/login
router.post("/login", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: "Email e senha são obrigatórios" });

  try {
    const resp = await axios.post(
      `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
      { email, password: senha },
      {
        headers: { apikey: SUPABASE_ANON_KEY, "Content-Type": "application/json" },
        timeout: 8000,
      }
    );
    const { access_token, user } = resp.data;
    return res.json({ access_token, user: { id: user.id, email: user.email } });
  } catch (err) {
    const msg = err.response?.data?.error_description || "Credenciais inválidas";
    return res.status(401).json({ erro: msg });
  }
});

// POST /api/auth/signup
router.post("/signup", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: "Email e senha são obrigatórios" });
  if (senha.length < 6) return res.status(400).json({ erro: "Senha deve ter ao menos 6 caracteres" });

  try {
    const resp = await axios.post(
      `${SUPABASE_URL}/auth/v1/signup`,
      { email, password: senha },
      {
        headers: { apikey: SUPABASE_ANON_KEY, "Content-Type": "application/json" },
        timeout: 8000,
      }
    );
    const { access_token, user } = resp.data;
    if (access_token) {
      return res.json({ access_token, user: { id: user.id, email: user.email } });
    }
    // E-mail de confirmação pendente
    return res.json({ message: "Verifique seu email para confirmar a conta", user: { email } });
  } catch (err) {
    const msg = err.response?.data?.msg || err.response?.data?.error_description || "Erro ao criar conta";
    return res.status(400).json({ erro: msg });
  }
});

module.exports = router;
