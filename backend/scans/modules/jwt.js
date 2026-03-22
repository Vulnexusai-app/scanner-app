/**
 * Módulo de Análise de JWT (JSON Web Tokens)
 */
async function testarJWT(url, body) {
    const findings = [];
    const jwtRegex = /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g;
    const text = typeof body === "string" ? body : JSON.stringify(body);
    
    const matches = text.match(jwtRegex);
    if (matches) {
        matches.forEach(token => {
            try {
                const parts = token.split(".");
                if (parts.length < 2) return;
                
                const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
                const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
                
                // 1. None Algorithm
                if (header.alg && header.alg.toLowerCase() === 'none') {
                    findings.push({
                        tipo: "JWT_NONE_ALG",
                        severidade: "CRITICAL",
                        descricao: "JWT utiliza algoritmo 'none' — bypass de assinatura possível"
                    });
                }

                // 2. No Expiry (from prompt)
                if (!payload.exp) {
                    findings.push({
                        tipo: "JWT_NO_EXPIRY",
                        severidade: "MEDIUM",
                        descricao: "Token JWT sem campo de expiração (exp)"
                    });
                }

                // 3. Weak HS Alg (from prompt)
                if (header.alg === "HS256") {
                    findings.push({
                        tipo: "JWT_HS_ALG_BRUTEFORCEABLE",
                        severidade: "HIGH",
                        descricao: "JWT utiliza algoritmo simétrico HS256 — suscetível a brute-force de segredo"
                    });
                }
                
            } catch (e) {}
        });
    }
    
    return findings;
}

module.exports = { testarJWT };
