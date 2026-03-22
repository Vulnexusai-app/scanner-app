/**
 * Módulo de Proteção SSRF e DNS
 */
const dns = require("dns").promises;

function isPrivateIP(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.|::1|fe80:)/.test(ip);
}

async function analisarSSRF(url, ambienteTeste) {
  const v = [];
  try {
    const host = new URL(url).hostname;
    const { address } = await dns.lookup(host);
    
    if (isPrivateIP(address) && !ambienteTeste) {
       v.push({ 
         tipo: "SSRF_ATEMPT", 
         severidade: "CRITICAL", 
         descricao: `Host resolve para IP privado (${address}) — Bloqueado por proteção SSRF` 
       });
    }
  } catch (e) {
    // Erro de DNS não é necessariamente SSRF, mas pode ser reportado se útil
  }
  return v;
}

module.exports = { analisarSSRF, isPrivateIP };
