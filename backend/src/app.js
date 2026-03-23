const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const config = require("./config");
const routes = require("./routes");
const { log } = require("./utils/logger");
const supabase = require("./services/supabase");
const Sentry = require("@sentry/node");
const { nodeProfilingIntegration } = require("@sentry/profiling-node");

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  integrations: [nodeProfilingIntegration()],
  tracesSampleRate: 0.1,
  environment: process.env.ENVIRONMENT || "production"
});


const path = require("path");
const app = express();
const { PORT } = config;

// Segurança e Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://plausible.io"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "data:image/png;base64"],
      connectSrc: ["'self'", "https://*.supabase.co", "https://api.groq.com", "https://generativelanguage.googleapis.com"],
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://vulnexusai.com'
  ],
  credentials: true
}));
app.use('/api/billing/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

const rateLimit = require('express-rate-limit')

// Proteção brute force no login
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,
  message: { error: 'Muitas tentativas. Aguarde 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
})

// Rate limit geral da API
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 30,
  message: { error: 'Muitas requisições. Aguarde um momento.' },
  standardHeaders: true,
  legacyHeaders: false
})

// Rate limit específico para forgot-password
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 3,
  message: { error: 'Limite de emails atingido. Aguarde 1 hora.' }
})

app.use('/api/', apiLimiter)
app.use('/api/auth/forgot-password', forgotPasswordLimiter)
app.use('/api/auth/login', authLimiter)
app.use('/api/auth/signup', authLimiter)


// Logs de Startup
log("info", "VulnexusAI SaaS Scanner v3.0 booting...");

// Servir Frontend (Static Files)
const frontendPath = path.join(__dirname, "../frontend");
app.use(express.static(frontendPath));

// Uso da API
app.get('/api/usage', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.json({ used: 0, limit: 1, plan: 'anonymous' })

  const { data: { user } } = await supabase.auth.getUser(token)
  if (!user) return res.status(401).json({ error: 'Não autenticado' })

  const today = new Date().toISOString().split('T')[0]
  const [usageResult, planResult] = await Promise.all([
    supabase.from('scan_usage').select('scan_count').eq('user_id', user.id).eq('date', today).single(),
    supabase.from('user_plans').select('scans_per_day, plan').eq('user_id', user.id).single()
  ])

  res.json({
    used: usageResult.data?.scan_count ?? 0,
    limit: planResult.data?.scans_per_day ?? 3,
    plan: planResult.data?.plan ?? 'free'
  })
})

// Rotas da API
app.use("/api", routes);

app.get("/health", (req, res) => {
  let pkgVersion = "5.0.0";
  try {
    pkgVersion = require("../package.json").version;
  } catch (e) {}
  res.json({
    status: 'ok',
    version: pkgVersion,
    timestamp: new Date().toISOString(),
    environment: process.env.ENVIRONMENT ?? 'production'
  })
});

// Sentry Error Handler (Deve vir após as rotas mas ANTES do fallback/404 se quisermos logar erros de roteamento)
Sentry.setupExpressErrorHandler(app);

// SPA Fallback: Qualquer rota GET que não seja arquivo estático e não seja API retorna index.html
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api")) return next();
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Handler Global de Erros
app.use((err, req, res, next) => {
  log("error", "unhandled_error", "-", `${err.message} | stack: ${err.stack}`);
  res.status(500).json({ erro: "Erro interno do servidor" });
});

// Catch-all 404 handler para rotas de API não definidas ou outros métodos
app.use((req, res) => {
  if (req.path.startsWith("/api")) {
    return res.status(404).json({ erro: "Rota de API não encontrada" });
  }
  res.status(404).sendFile('404.html', { root: frontendPath });
});

app.listen(PORT, () => {
    log("info", `Servidor rodando na porta ${PORT}`);
});

module.exports = app;
