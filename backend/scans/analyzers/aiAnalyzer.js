/**
 * VulnexusAI AI Analyzer — v4.0
 * Gemini primary → Groq fallback → Local fallback
 */
const axios = require("axios");

// ─── PROMPT ────────────────────────────────────────────────────────────────────
function montarPrompt(relatorio) {
  const {
    target, status, tempo_resposta_ms, score_seguranca, nivel_risco,
    total_problemas, alto_risco, medio_risco, baixo_risco,
    issues, headers_recebidos, body_snippet, ambiente_teste, ambiente_nota,
  } = relatorio;

  const listaProblemas = issues && issues.length > 0
    ? issues.map((i, n) => `${n + 1}. ${i}`).join("\n")
    : "Nenhum problema encontrado.";

  const cabecalhosPresentes = (headers_recebidos || []).join(", ") || "Não disponível";
  const bodyInfo = body_snippet
    ? `\n=== SNIPPET DO BODY (primeiros 500 chars) ===\n${body_snippet}`
    : "";

  const aviso_ambiente = ambiente_teste
    ? "\n⚠️  ATENÇÃO: Esta é uma API de teste/sandbox. Adapte sua análise para contexto educativo/informativo.\n"
    : "";

  return `Você é um especialista sênior em segurança de APIs (OWASP, SANS, NIST). Analise o relatório abaixo e responda EXCLUSIVAMENTE em português do Brasil.${aviso_ambiente}

=== DADOS DO SCAN ===
URL analisada: ${target}
Status HTTP: ${status}
Tempo de resposta: ${tempo_resposta_ms}ms
Score de segurança: ${score_seguranca}/100
Nível de risco geral: ${nivel_risco}
Total de problemas: ${total_problemas} (${alto_risco} HIGH · ${medio_risco} MEDIUM · ${baixo_risco} LOW)

=== PROBLEMAS DETECTADOS ===
${listaProblemas}

=== HEADERS RECEBIDOS ===
${cabecalhosPresentes}
${bodyInfo}

=== SUA RESPOSTA DEVE CONTER ===

## 🎯 Resumo Executivo
Uma frase clara sobre o estado de segurança desta API.

## 🔴 Riscos Críticos (HIGH)
Para cada problema HIGH: explique o risco, mostre um exemplo real de ataque, e forneça o código de correção.

## 🟡 Riscos Moderados (MEDIUM)
Para cada problema MEDIUM: explique brevemente e dê a correção.

## 🟢 Informativo (LOW)
Liste os pontos LOW resumidamente.

## 🛡️ Plano de Ação
Top 3 correções prioritárias com código real (Node.js/Express quando aplicável).

## 📊 Avaliação Final
Score: ${score_seguranca}/100 — diga se é aceitável para produção ou não.

Seja direto, técnico e use exemplos de código reais. Máximo 800 palavras.`;
}

// ─── GEMINI ────────────────────────────────────────────────────────────────────
async function analisarComGemini(relatorio, apiKey) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const resposta = await axios.post(url,
    {
      contents: [{ parts: [{ text: montarPrompt(relatorio) }] }],
      generationConfig: { maxOutputTokens: 2048, temperature: 0.25, topP: 0.9 },
    },
    { timeout: 35000 }
  );
  const texto = resposta.data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!texto) throw new Error("Gemini retornou resposta vazia");
  return texto.trim();
}

// ─── GROQ ──────────────────────────────────────────────────────────────────────
async function analisarComGroq(relatorio, apiKey) {
  const resposta = await axios.post(
    "https://api.groq.com/openai/v1/chat/completions",
    {
      model: "llama-3.3-70b-versatile",
      messages: [
        {
          role: "system",
          content: "Você é um especialista sênior em segurança de APIs (OWASP, pentest, hardening). Responda SEMPRE em português do Brasil. Seja técnico, direto e forneça exemplos de código.",
        },
        { role: "user", content: montarPrompt(relatorio) },
      ],
      max_tokens: 2048,
      temperature: 0.25,
    },
    {
      timeout: 35000,
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    }
  );
  const texto = resposta.data?.choices?.[0]?.message?.content;
  if (!texto) throw new Error("Groq retornou resposta vazia");
  return texto.trim();
}

// ─── FALLBACK LOCAL ────────────────────────────────────────────────────────────
function gerarAnaliseLocal(relatorio) {
  const { nivel_risco, score_seguranca, total_problemas, alto_risco, medio_risco, baixo_risco, issues, ambiente_teste } = relatorio;

  if (ambiente_teste) {
    return `## 🎯 Resumo Executivo\nAmbiente de teste/sandbox detectado. Análise tem caráter informativo.\n\n` +
      `**Score:** ${score_seguranca}/100 · **Problemas:** ${total_problemas}\n\n` +
      `> Nota: Em ambientes de produção, corrija todos os headers de segurança antes do go-live.`;
  }

  if (total_problemas === 0) {
    return `## 🎯 Resumo Executivo\n✅ Nenhuma vulnerabilidade crítica detectada. Score: ${score_seguranca}/100.\n\n` +
      `## 🛡️ Recomendações Gerais\n- Mantenha as dependências atualizadas (npm audit)\n- Ative monitoramento de anomalias\n- Realize pentests periódicos\n\n` +
      `## 📊 Avaliação Final\nScore ${score_seguranca}/100 — **Adequado para produção** com manutenção contínua.`;
  }

  const lista = (issues || []).map((i, n) => `${n + 1}. ${i}`).join("\n");
  const isCritico = alto_risco > 0;

  return `## 🎯 Resumo Executivo\n` +
    `${isCritico ? "🔴 API com vulnerabilidades CRÍTICAS" : "🟡 API com vulnerabilidades moderadas"}. Score: ${score_seguranca}/100.\n\n` +
    `**Distribuição:** ${alto_risco} HIGH · ${medio_risco} MEDIUM · ${baixo_risco} LOW\n\n` +
    `## 🔍 Problemas Detectados\n${lista}\n\n` +
    `## 🛡️ Plano de Ação Prioritário\n` +
    `1. Adicione headers de segurança via middleware (ex: \`helmet\` no Node.js)\n` +
    `2. Configure CORS restrito à sua origem\n` +
    `3. Ative rate limiting (ex: \`express-rate-limit\`)\n\n` +
    `## 📊 Avaliação Final\nScore ${score_seguranca}/100 — ${score_seguranca < 50 ? "**NÃO recomendado para produção**" : "**Requer correções antes do go-live**"}.\n\n` +
    `> ⚠️ Análise local (IAs indisponíveis). Configure GEMINI_API_KEY ou GROQ_API_KEY para análise detalhada.`;
}

// ─── ORQUESTRADOR ──────────────────────────────────────────────────────────────
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

  // Fallback local
  const analise = gerarAnaliseLocal(relatorio);
  return { analise, provedor: "local" };
}

module.exports = { analisarComIA };
