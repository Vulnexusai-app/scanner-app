const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const config = require("./config");
const routes = require("./routes");
const { log } = require("./utils/logger");

const app = express();
const { PORT } = config;

// Segurança e Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Logs de Startup
log("info", "VulnexusAI SaaS Scanner v3.0 booting...");

// Rotas da API
app.use("/api", routes);

// Rota raiz e Health check
app.get("/", (req, res) => res.json({ status: "ok", message: "VulnexusAI API v3.0" }));
app.get("/health", (req, res) => res.json({ status: "ok", uptime: process.uptime() }));

// Handler Global de Erros
app.use((err, req, res, next) => {
  log("error", "unhandled_error", "-", err.message);
  res.status(500).json({ erro: "Erro interno do servidor" });
});

app.listen(PORT, () => {
    log("info", `Servidor rodando na porta ${PORT}`);
});

module.exports = app;
