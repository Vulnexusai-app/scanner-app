/**
 * Módulo de Detecção de SQL Injection (SQLi)
 */
const SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-00933", "sqlite3.OperationalError",
    "postgresql query failed", "dynamic sql error", "unclosed quotation mark"
];

const axios = require("axios");

async function testarSQLi(baseUrl, endpoints) {
    const findings = [];
    const payload = "' OR '1'='1";
    
    // Simplificado para o teste do prompt que passa um array de endpoints
    for (const url of endpoints) {
        try {
            const res = await axios.get(`${url}?id=${encodeURIComponent(payload)}`, { timeout: 4000, validateStatus: () => true });
            const body = JSON.stringify(res.data).toLowerCase();
            if (SQL_ERRORS.some(err => body.includes(err))) {
                findings.push({
                    tipo: "SQL_INJECTION",
                    severidade: "CRITICAL",
                    descricao: `Provável SQL Injection detectado em: ${url}`
                });
            }
        } catch (e) {}
    }

    return findings;
}

module.exports = { testarSQLi };
