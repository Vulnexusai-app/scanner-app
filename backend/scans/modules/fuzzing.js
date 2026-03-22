/**
 * Módulo de Fuzzing de Parâmetros
 */
const PARAMETROS_FUZZING = ["?debug=true", "?test=1", "?admin=true", "?dev=1"];

async function runFuzzing(baseUrl, requestFn) {
  const achados = [];
  for (const param of PARAMETROS_FUZZING) {
    try {
      const res = await requestFn(baseUrl + param, 4000);
      if (res.status === 200 && res.data && JSON.stringify(res.data).length > 200) {
        achados.push({ 
          tipo: "FUZZING_DISCOVERY", 
          severidade: "MEDIUM", 
          descricao: `Comportamento anômalo detectado com parâmetro: ${param}` 
        });
      }
    } catch (e) {}
  }
  return achados;
}

module.exports = { runFuzzing };
