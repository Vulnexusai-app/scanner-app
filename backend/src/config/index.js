require("dotenv").config();

module.exports = {
  PORT: process.env.PORT || 3000,
  SUPABASE_URL: process.env.SUPABASE_URL || "",
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY || "",
  SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY || "",
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || "",
  GROQ_API_KEY: process.env.GROQ_API_KEY || "",
  APP_URL: process.env.APP_URL || "http://localhost:3000",
  ENVIRONMENT: process.env.ENVIRONMENT || "development",
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY || "",
  STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY || "",
  STRIPE_PRICE_ID: process.env.STRIPE_PRICE_ID || "",
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET || "",
  LIMITES: { free: 3, pro: Infinity },
};
