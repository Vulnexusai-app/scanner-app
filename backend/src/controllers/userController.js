const db = require("../services/dbService");
const config = require("../config");

const { LIMITES } = config;

async function getMe(req, res) {
  try {
    const usuario = await db.buscarOuCriarUsuario(req.usuario.id, req.usuario.email);
    return res.json({ usuario });
  } catch (erro) {
    return res.status(500).json({ erro: erro.message });
  }
}

async function getUsage(req, res) {
  try {
    const usuario = await db.buscarOuCriarUsuario(req.usuario.id, req.usuario.email);
    const scansHoje = await db.contarScansHoje(req.usuario.id);
    const limite = LIMITES[usuario.plan] === Infinity ? "ilimitado" : LIMITES[usuario.plan];
    return res.json({ 
      plano: usuario.plan, 
      scans_hoje: scansHoje, 
      limite_diario: limite, 
      restantes: limite === "ilimitado" ? "ilimitado" : Math.max(0, limite - scansHoje) 
    });
  } catch (erro) {
    return res.status(500).json({ erro: erro.message });
  }
}

module.exports = { getMe, getUsage };
