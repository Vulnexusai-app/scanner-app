/**
 * Módulo de Análise de Cabeçalhos HTTP
 */
const CABECALHOS_SEGURANCA = [
  { nome: "x-frame-options",          sev: "MEDIUM", desc: "X-Frame-Options ausente — vulnerável a Clickjacking" },
  { nome: "content-security-policy",  sev: "HIGH",   desc: "Content-Security-Policy ausente — vulnerável a XSS" },
  { nome: "x-content-type-options",   sev: "LOW",    desc: "X-Content-Type-Options ausente — MIME sniffing possível" },
  { nome: "strict-transport-security", sev: "MEDIUM", desc: "HSTS ausente — risco de downgrade para HTTP" },
  { nome: "access-control-allow-origin", sev: "HIGH",  desc: "CORS aberto (*) — qualquer origem pode ler dados" },
];

function analisarHeaders(headers, url) {
  const v = [];
  CABECALHOS_SEGURANCA.forEach(h => {
    const val = headers[h.nome];
    if (!val) {
      v.push({ tipo: "MISSING_HEADER", header: h.nome, severidade: h.sev, descricao: h.desc });
    } else if (h.nome === "content-security-policy" && (val.includes("'unsafe-inline'") || val.includes("*"))) {
      v.push({ tipo: "WEAK_CSP", header: "CSP", severidade: "MEDIUM", descricao: "CSP Fraco (unsafe-inline ou wildcard detectado)" });
    }
    // Lógica de CORS movida para cors.js conforme solicitado, 
    // mas mantida aqui se necessário para compatibilidade ou removida se o orquestrador chamar ambos.
    // O usuário pediu especificamente: "modules/cors.js ← lógica CORS existente"
  });

  if (headers["server"]) v.push({ tipo: "FINGERPRINT", header: "Server", severidade: "LOW", descricao: `Banner do servidor exposto: ${headers["server"]}` });
  
  const cookie = headers["set-cookie"];
  if (cookie) {
    const s = Array.isArray(cookie) ? cookie.join(" ") : cookie;
    const sLower = s.toLowerCase();
    if (!sLower.includes("httponly")) v.push({ tipo: "INSECURE_COOKIE", severidade: "MEDIUM", descricao: "Cookie sem flag HttpOnly" });
    if (!sLower.includes("secure") && url.startsWith("https")) v.push({ tipo: "INSECURE_COOKIE", severidade: "MEDIUM", descricao: "Cookie sem flag Secure em conexão HTTPS" });
  }

  return v;
}

module.exports = { analisarHeaders };
