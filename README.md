# 🛡️ VulnexusAI — AI-Powered API Security Scanner

![Status](https://img.shields.io/badge/status-active-success)
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

## 🌐 Demo Online

👉 [https://vulnexusai.com/](https://vulnexusai.com/)


## ⚙️ Stack

* **Frontend**: HTML5, Vanilla CSS (Premium Dark + Glassmorphism).
* **Backend**: Node.js, Express.
* **Database**: Supabase.
* **Infra**: Railway.
* **Intelligence**: IA (Gemini / Groq).

---

## 🧪 Como rodar localmente

```bash
git clone https://github.com/seu-usuario/vulnexusai
cd vulnexusai
npm install
```

---

### 🔐 Configurar variáveis

Crie um arquivo `.env` na pasta `backend`:

```env
SUPABASE_URL=seu_url
SUPABASE_SERVICE_ROLE_KEY=sua_key
GEMINI_API_KEY=sua_key
GROQ_API_KEY=sua_key
```

---

### ▶️ Rodar

```bash
npm run dev
```

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
