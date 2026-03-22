const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const config = require("./config");
const routes = require("./routes");
const { log } = require("./utils/logger");

const path = require("path");
const app = express();
const { PORT } = config;

// Segurança e Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Permitir carregar scripts/CSS externos se necessário
}));
app.use(cors());
app.use(express.json());

// Logs de Startup
log("info", "VulnexusAI SaaS Scanner v3.0 booting...");

// Servir Frontend (Static Files)
const frontendPath = path.join(__dirname, "../frontend");
app.use(express.static(frontendPath));

// Rotas da API
app.use("/api", routes);

// Rota raiz - Serve o index.html se não for API
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

app.get("/health", (req, res) => res.json({ status: "ok", uptime: process.uptime() }));

// Handler Global de Erros
app.use((err, req, res, next) => {
  log("error", "unhandled_error", "-", `${err.message} | stack: ${err.stack}`);
  res.status(500).json({ erro: "Erro interno do servidor" });
});

app.listen(PORT, () => {
    log("info", `Servidor rodando na porta ${PORT}`);
});

module.exports = app;
