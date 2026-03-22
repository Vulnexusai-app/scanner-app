/**
 * Módulo de Enumeração de Endpoints
 */
const ENDPOINTS_ENUMERACAO = ["/admin", "/login", "/debug", "/config", "/api/v1", "/.env", "/phpinfo.php", "/wp-admin"];

async function runEnumeration(baseUrl, requestFn) {
  const achados = [];
  const tests = ENDPOINTS_ENUMERACAO.map(async (path) => {
    try {
      const res = await requestFn(baseUrl + path, 3000);
      if ([200, 403, 401].includes(res.status)) {
        achados.push({ 
          tipo: "ENDPOINT_ENUMERATION", 
          severidade: "LOW", 
          descricao: `Possível superfície de ataque encontrada: ${path} (Status ${res.status})` 
        });
      }
    } catch (e) {}
  });
  
  // Limitar concorrência para não sobrecarregar o alvo
  await Promise.all(tests.slice(0, 5)); 
  return achados;
}

module.exports = { runEnumeration };
