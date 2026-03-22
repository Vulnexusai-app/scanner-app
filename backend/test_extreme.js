const path = require("path");
const scannerPath = path.resolve(__dirname, "scans/engine/scanner.js");
const aiPath = path.resolve(__dirname, "scans/analyzers/aiAnalyzer.js");
const configPath = path.resolve(__dirname, "src/config/index.js");

console.log("DEBUG: Resolving paths...");
console.log("  Scanner:", scannerPath);
console.log("  AI:", aiPath);

const { escanear } = require(scannerPath);
const { analisarComIA } = require(aiPath);
const config = require(configPath);

async function validate() {
  console.log("🔥 [VALIDAÇÃO EXTREME] Iniciando bateria de testes profissionais...");
  const cenarios = [
    { name: "Cenário 1: Erro Internal Server 500 (Sandbox)", url: "https://httpbin.org/status/500" },
    { name: "Cenário 2: API Pública Simples (Sandbox)", url: "https://reqres.in/api/users/2" },
    { name: "Cenário 3: Alvo Real de Produção", url: "https://google.com" }
  ];

  for (const c of cenarios) {
    try {
      console.log(`\n🧪 Testando ${c.name}...`);
      const res = await escanear(c.url);
      console.log(`📊 Result: Contexto=${res.contexto} | Score=${res.score} | Nível=${res.nivel}`);
      console.log(`⚠️  Vulns: ${res.resumo.criticas}C, ${res.resumo.moderadas}M, ${res.resumo.baixas}B`);
      if (res.correlacoes.length > 0) console.log(`🧠 Correlações: ${res.correlacoes.join(" | ")}`);
      
      const { analise } = await analisarComIA(res, config);
      const prioritizeLines = analise.split("\n").filter(l => l.includes("🔴") || l.includes("🟡") || l.includes("🟢")).slice(0, 3);
      prioritizeLines.forEach(l => console.log(`   ${l}`));
    } catch (e) {
      console.error(`❌ Erro no cenário ${c.name}:`, e.message);
    }
  }
}
validate();
