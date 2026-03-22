/**
 * Módulo de Análise de CORS
 */
function analisarCORS(headers) {
  const v = [];
  const corsHeader = headers["access-control-allow-origin"];
  const methods = headers["access-control-allow-methods"];
  
  if (corsHeader === "*") {
    v.push({ 
      tipo: "OPEN_CORS", 
      header: "CORS", 
      severidade: "HIGH", 
      descricao: "CORS Aberto (Access-Control-Allow-Origin: *) — permite que qualquer site leia dados desta API" 
    });
  }

  if (methods && methods.includes("*")) {
    v.push({
      tipo: "EXCESSIVE_CORS_METHODS",
      header: "CORS",
      severidade: "MEDIUM",
      descricao: "Métodos CORS excessivos (Wildcard em Access-Control-Allow-Methods)"
    });
  }

  return v;
}

module.exports = { analisarCORS };
