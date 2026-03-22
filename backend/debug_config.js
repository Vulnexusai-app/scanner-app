const config = require('./src/config');
console.log('--- DEBUG CONFIG ---');
console.log('PORT:', JSON.stringify(config.PORT));
console.log('SUPABASE_URL:', JSON.stringify(config.SUPABASE_URL));
console.log('SERVICE_KEY_LEN:', config.SUPABASE_SERVICE_ROLE_KEY.length);
console.log('--- END ---');
