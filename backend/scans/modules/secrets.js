/**
 * Módulo de Análise de Segredos e Vazamento de Dados no Corpo
 */
const PADROES_SEGREDOS = [
  { id: "JWT_TOKEN",     re: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/, sev: "CRITICAL", desc: "Token JWT detectado na resposta" },
  { id: "BEARER_TOKEN",  re: /Bearer\s+[A-Za-z0-9-_=.]+/, sev: "CRITICAL", desc: "Bearer Token exposto" },
  { id: "AWS_KEY",       re: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/, sev: "CRITICAL", desc: "Chave AWS exposta" },
  { id: "GOOGLE_KEY",    re: /AIza[0-9A-Za-z\-_]{35}/, sev: "CRITICAL", desc: "Chave Google API detectada" },
  { id: "GENERIC_KEY",   re: /(?:key|secret|passwd|password|token)["']\s*[:=]\s*["']([^"']{10,})["']/i, sev: "CRITICAL", desc: "Credencial ou Chave de API detectada" },
  { id: "PRIVATE_KEY",   re: /-----BEGIN (?:RSA|EC|PRIVATE|OPENSSH) KEY-----/, sev: "CRITICAL", desc: "Chave Privada exposta" }
];

function analisarCorpo(body) {
  const v = [];
  if (!body) return v;
  const texto = typeof body === "string" ? body : JSON.stringify(body);
  
  PADROES_SEGREDOS.forEach(p => {
    if (p.re.test(texto)) {
      v.push({ tipo: "SENSITIVE_DATA", severidade: p.sev, descricao: p.desc });
    }
  });

  if (texto.includes("stack trace") || texto.includes("at line") || texto.includes("SQL syntax")) {
    v.push({ tipo: "SERVER_ERROR_DETAIL", severidade: "HIGH", descricao: "Stack trace ou erro detalhado exposto no corpo" });
  }

  return v;
}

module.exports = { analisarCorpo };
