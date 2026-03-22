/**
 * VulnexusAI AI Analyzer — v4.0
 * Gemini primary → Groq fallback → Local fallback
 */
const axios = require("axios");

// ─── PROMPT ────────────────────────────────────────────────────────────────────
function montarPrompt(scan) {
  const {
    target,
  } = scan;
  const vulnsRaw = scan.vulnerabilidades || {};
  const listaVulns = [
    ...(vulnsRaw.criticas || []).map(v => `[🔴 ALTO/CRÍTICO] ${v.descricao}`),
    ...(vulnsRaw.moderadas || []).map(v => `[🟡 MÉDIO] ${v.descricao}`),
    ...(vulnsRaw.baixas || []).map(v => `[🟢 BAIXO] ${v.descricao}`),
  ].join("\n");

  return `Você é o **VULNEXUSAI_SECURITY_AUDITOR**, um especialista sênior em segurança ofensiva.
Analise o relatório técnico abaixo e forneça uma auditoria de nível enterprise.

=== RELATÓRIO TÉCNICO ===
Target: ${target}
Score: ${scan.score}/100 | Nível: ${scan.nivel}
Contexto: ${scan.contexto}

Vulnerabilidades Detectadas:
${listaVulns}

Combinações/Correlações Encontrativas:
${(scan.correlacoes || []).join("\n")}

Headers Recebidos: ${(scan.headers_recebidos || []).join(", ")}
Body Snippet: ${scan.body_snippet}

=== INSTRUÇÕES DE RESPOSTA (OBRIGATÓRIO) ===
Responda em PORTUGUÊS (Brasil).
Sua resposta deve ser dividida exatamente nestas seções:

## 🎯 Resumo Executivo
Uma análise profissional de 2-3 frases sobre a postura de segurança do alvo e o risco ao negócio.

## ⚠️ Plano de Ação Prioritário
Ordene as vulnerabilidades pelo impacto REAL. Use os ícones exatamente como abaixo:
🔴 **Corrigir Imediatamente:** (Vulnerabilidades críticas/altas com impacto direto)
🟡 **Corrigir em Seguida:** (Vulnerabilidades médias e correlações de segurança)
🟢 **Melhorias Futuras:** (Baixo risco e boas práticas)

Para cada item, explique:
- **O que é:** Tecnicamente, o que foi encontrado.
- **Impacto:** Como um atacante exploraria (ex: PoC conceitual).
- **Remediação:** Código real ou configuração para corrigir.

## 💻 Implementação Consolidada
Forneça um bloco de código (ex: middleware de segurança ou config de servidor) que resolva os principais problemas de uma vez.

## 📊 Veredito do Auditor
Dê uma nota final e diga se o endpoint está pronto para produção.

Seja técnico, agressivo na detecção e preciso na correção.`;
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
