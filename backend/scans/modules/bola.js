/**
 * Módulo de BOLA (Broken Object Level Authorization)
 */
const axios = require("axios");

async function testarBOLA(baseUrl, endpoints) {
    const findings = [];
    
    for (const url of endpoints) {
        const match = url.match(/\/(\d+)($|\/)/);
        if (match) {
            const id = parseInt(match[1]);
            const nextId = id + 1;
            const testUrl = url.replace(match[1], nextId);
            
            try {
                const res = await axios.get(testUrl, { timeout: 3000, validateStatus: () => true });
                if (res.status === 200) {
                    findings.push({
                        tipo: "BOLA_NUMERIC_ID",
                        severidade: "HIGH",
                        descricao: `Recurso de outro ID acessível sem autenticação: ${testUrl}`
                    });
                }
            } catch (e) {}
        }
    }
    
    return findings;
}

module.exports = { testarBOLA };
