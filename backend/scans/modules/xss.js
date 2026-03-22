/**
 * Módulo de Detecção de Cross-Site Scripting (XSS)
 */
const axios = require("axios");

async function testarXSS(baseUrl, endpoints) {
    const findings = [];
    const xssProbe = "z'x\"y<v>w";
    
    for (const url of endpoints) {
        try {
            const res = await axios.get(`${url}?q=${encodeURIComponent(xssProbe)}`, { timeout: 4000, validateStatus: () => true });
            const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            if (body.includes(xssProbe)) {
                findings.push({
                    tipo: "XSS_REFLECTED",
                    severidade: "HIGH",
                    descricao: `XSS Refletido detectado em: ${url}`
                });
            }
        } catch (e) {}
    }

    return findings;
}

module.exports = { testarXSS };
