# ⚠️ Repositório Legado

> **Este código NÃO está mais em produção.** O produto atual da VulnexusAI roda em
> **https://vulnexusai.com/** (reescrito em **Next.js 16**, sem billing).
>
> Este repositório é mantido **exclusivamente como referência histórica** da primeira
> versão do scanner (Node.js/Express + Supabase + Stripe). Não use este código para
> desenvolvimento novo — ele está desatualizado e desativado.

**Status:** arquivado / apenas leitura

---

# 🛡️ VulnexusAI — Scanner de API (Versão Legada)

![Status](https://img.shields.io/badge/status-archived-inactive)
![Security](https://img.shields.io/badge/security-OWASP%20aligned-red)
![AI](https://img.shields.io/badge/AI-Gemini%20%2F%20Groq-purple)
![Deploy](https://img.shields.io/badge/deploy-Railway-black)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 🚀 Sobre o projeto

O **VulnexusAI** é um scanner de segurança de APIs com inteligência artificial, projetado para detectar vulnerabilidades reais com base no padrão OWASP e fornecer recomendações práticas de correção.

---

## 🧠 Principais recursos

* 🔍 **Scanner automático de APIs**: Varredura rápida e profunda de endpoints.
* 🛡️ **Detecção baseada no OWASP Top 10**: Foco nas vulnerabilidades mais críticas da web.
* 🤖 **Análise inteligente com IA**: Relatórios detalhados gerados por Gemini e Groq.
* 📊 **Score de segurança (0–100)**: Avaliação quantitativa do risco (Enterprise Score).
* 💀 **Detecção de segredos**: Identificação de API Keys, Tokens e JWT expostos.
* ⚡ **Fuzzing leve e enumeração**: Descoberta de parâmetros e endpoints ocultos.
* 🧠 **Correlação de vulnerabilidades**: Identificação de combinações perigosas de falhas.
* 🚫 **Proteção contra SSRF**: Motor de busca protegido contra ataques de rede interna.

---

## 📸 Preview

Acesse a dashboard moderna com interface futurista e efeitos de Glassmorphism.

---

## 🔗 Produto em produção

👉 [https://vulnexusai.com/](https://vulnexusai.com/) — o scanner atual (Next.js 16)

## ⚙️ Stack

* **Frontend**: HTML5, Vanilla CSS (Premium Dark + Glassmorphism).
* **Backend**: Node.js, Express.
* **Database**: Supabase.
* **Infra**: Railway.
* **Intelligence**: IA (Gemini / Groq).

---

## 🧪 Como rodar localmente

> ⚠️ **Nota:** este repo é legado — rodar o scanner aqui localmente não é mais suportado.
> A configuração abaixo é apenas referência (as chaves variáveis estão documentadas em
> [`backend/.env.example`](backend/.env.example)).

```bash
git clone https://github.com/Vulnexusai-app/scanner-app.git
cd scanner-app
npm install
cd backend
npm install
npm run dev
```

O app espera um `.env` em `backend/` com as chaves de Supabase, IA, Stripe e Resend
(variáveis e placeholders em [`backend/.env.example`](backend/.env.example)). O schema
SQL completo do Supabase está em `backend/database/migrations/`.

---

## 📊 Exemplo de saída

```json
{
  "score": 42,
  "nivel": "CRÍTICO",
  "resumo": {
    "criticas": 2,
    "moderadas": 3,
    "baixas": 4
  }
}
```

---

## 🛡️ Segurança do Scanner

* Validação rigorosa de URL.
* Rate limiting e Timeout configurados.
* Proteção contra SSRF via DNS Lookup e IP Filtering.
* Headers de segurança (Helmet, CORS restrito).

---

## 🤖 Inteligência Artificial

A IA é integrada para transformar dados brutos em inteligência acionável:
* Priorização real com ícones (🔴/🟡/🟢).
* Explicações técnicas e impactos no negócio.
* Sugestão de código real para mitigação imediata.

---

## 🏢 VulnexusAI Security Labs

Projeto focado em pesquisa e desenvolvimento de soluções de segurança baseadas em IA.

---

## 📄 Licença

Este projeto está sob a licença [MIT](LICENSE).
