/**
 * Módulo de Verificação de Rate Limiting
 */
async function testarRateLimit(url, requestFn) {
    const findings = [];
    const requests = [];
    
    // Dispara 5 requisições rápidas
    for (let i = 0; i < 5; i++) {
        requests.push(requestFn(url, 2000));
    }
    
    try {
        const results = await Promise.all(requests);
        const blocked = results.some(r => r.status === 429);
        
        if (!blocked) {
            findings.push({
                tipo: "NO_RATE_LIMIT",
                severidade: "LOW",
                descricao: "Ausência de Rate Limiting detectada (múltiplas req/s aceitas sem 429)"
            });
        }
    } catch (e) {}
    
    return findings;
}

module.exports = { testarRateLimit };
