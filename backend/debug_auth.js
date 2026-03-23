const axios = require('axios');
require('dotenv').config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || SUPABASE_SERVICE_ROLE_KEY;

async function testSignup() {
  console.log('Testing signup with:');
  console.log('URL:', SUPABASE_URL);
  console.log('Key:', SUPABASE_ANON_KEY.substring(0, 10) + '...');

  try {
    const resp = await axios.post(
      `${SUPABASE_URL}/auth/v1/signup`,
      { 
        email: 'teste_debug@vulnexus.com', 
        password: 'senha123',
        options: {
          emailRedirectTo: 'https://vulnexusai.com/index.html'
        }
      },
      {
        headers: { apikey: SUPABASE_ANON_KEY, "Content-Type": "application/json" },
        timeout: 8000,
      }
    );
    console.log('Success:', resp.data);
  } catch (err) {
    console.error('Error Status:', err.response?.status);
    console.error('Error Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Error Message:', err.message);
  }
}

testSignup();
