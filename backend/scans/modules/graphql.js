/**
 * Módulo de Segurança GraphQL
 */
const axios = require("axios");

async function testarGraphQL(url) {
    const findings = [];
    const introQuery = '{"query":"{ __schema { types { name } } }"}';
    const endpoints = [url.replace(/\/$/, "") + "/graphql", url.replace(/\/$/, "") + "/api/graphql", url];
    
    for (const gqlUrl of endpoints) {
        try {
            const res = await axios.post(gqlUrl, JSON.parse(introQuery), { 
                headers: { "Content-Type": "application/json" },
                timeout: 4000,
                validateStatus: () => true
            });
            
            if (res.status === 200 && JSON.stringify(res.data).includes("__schema")) {
                findings.push({
                    tipo: "GRAPHQL_INTROSPECTION",
                    severidade: "MEDIUM",
                    descricao: `GraphQL Introspection habilitada em: ${gqlUrl}`
                });
                break;
            }
        } catch (e) {}
    }
    
    return findings;
}

module.exports = { testarGraphQL };
