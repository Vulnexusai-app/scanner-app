const axios = require("axios");

function montarPrompt(relatorio) {
  const listaProblemas = relatorio.issues.length > 0
    ? relatorio.issues.map((i, n) => `${n + 1}. ${i}`).join("\n")
    : "Nenhum problema encontrado.";

  return `Analise este relatório de segurança de API e responda em português:

=== DADOS DO SCAN ===
URL analisada: ${relatorio.target}
Status HTTP: ${relatorio.status}
Tempo de resposta: ${relatorio.tempo_resposta_ms}ms
Score de segurança: ${relatorio.score_seguranca}/100
Nível de risco: ${relatorio.nivel_risco}
Total de problemas: ${relatorio.total_problemas}

=== PROBLEMAS ENCONTRADOS ===
${listaProblemas}

=== SUA TAREFA ===
Para cada problema encontrado:
1. Explique o risco em linguagem simples (como se fosse para um iniciante)
2. Dê um exemplo de impacto no mundo real
3. Forneça uma correção clara (com código se possível)

Se não houver problemas, parabenize e dê dicas gerais de segurança.
Seja direto, claro e use exemplos práticos.`;
}

async function analisarComGemini(relatorio, apiKey) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const resposta = await axios.post(url,
    { contents: [{ parts: [{ text: montarPrompt(relatorio) }] }],
      generationConfig: { maxOutputTokens: 1024, temperature: 0.3 } },
    { timeout: 30000 }
  );
  const texto = resposta.data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!texto) throw new Error("Gemini retornou resposta vazia");
  return texto.trim();
}

async function analisarComGroq(relatorio, apiKey) {
  const resposta = await axios.post(
    "https://api.groq.com/openai/v1/chat/completions",
    { model: "llama-3.3-70b-versatile",
      messages: [
        { role: "system", content: "Você é um especialista em segurança de APIs. Responda sempre em português." },
        { role: "user", content: montarPrompt(relatorio) },
      ],
      max_tokens: 1024, temperature: 0.3 },
    { timeout: 30000,
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" } }
  );
  const texto = resposta.data?.choices?.[0]?.message?.content;
  if (!texto) throw new Error("Groq retornou resposta vazia");
  return texto.trim();
}

async function analisarComIA(relatorio, config) {
  const { GEMINI_API_KEY, GROQ_API_KEY } = config;

  // Tenta Gemini primeiro
  if (GEMINI_API_KEY) {
    try {
      const analise = await analisarComGemini(relatorio, GEMINI_API_KEY);
      return { analise, provedor: "gemini" };
    } catch (erro) {
      console.warn(`[IA] Gemini falhou: ${erro.message}`);
    }
  }

  // Fallback para Groq
  if (GROQ_API_KEY) {
    try {
      const analise = await analisarComGroq(relatorio, GROQ_API_KEY);
      return { analise, provedor: "groq" };
    } catch (erro) {
      console.warn(`[IA] Groq falhou: ${erro.message}`);
    }
  }

  // Nenhuma IA disponível — gera resumo baseado nos dados do scan
  const analise = gerarAnaliseLocal(relatorio);
  return { analise, provedor: "local" };
}

function gerarAnaliseLocal(relatorio) {
  const { nivel_risco, score_seguranca, total_problemas, issues } = relatorio;
  if (total_problemas === 0) {
    return `✅ Nenhum problema crítico encontrado. Score: ${score_seguranca}/100. Mantenha suas bibliotecas atualizadas e monitore sua API regularmente.`;
  }
  const lista = (issues || []).slice(0, 5).map(i => `• ${i}`).join("\n");
  return `⚠️ Foram encontrados ${total_problemas} problema(s) de segurança. Nível de risco: ${nivel_risco}. Score: ${score_seguranca}/100.\n\nPrincipais issues:\n${lista}\n\n💡 Recomendação: corrija os headers de segurança ausentes e revise as configurações de CORS e autenticação da sua API.`;
}

module.exports = { analisarComIA };
