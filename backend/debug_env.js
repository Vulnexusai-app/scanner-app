const config = require("./src/config");
console.log("--- DEBUG ENV ---");
console.log("PORT:", config.PORT);
console.log("SUPABASE_URL:", config.SUPABASE_URL ? "CONFIGURADO (" + config.SUPABASE_URL.substring(0, 15) + "...)" : "AUSENTE");
console.log("SUPABASE_SERVICE_ROLE_KEY:", config.SUPABASE_SERVICE_ROLE_KEY ? "CONFIGURADO (***)" : "AUSENTE");
console.log("GEMINI_API_KEY:", config.GEMINI_API_KEY ? "CONFIGURADO (***)" : "AUSENTE");
console.log("GROQ_API_KEY:", config.GROQ_API_KEY ? "CONFIGURADO (***)" : "AUSENTE");
console.log("------------------");
