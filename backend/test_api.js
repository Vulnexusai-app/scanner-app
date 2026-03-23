const axios = require('axios');

async function testApi() {
  console.log('Testing /api/auth/signup...');
  try {
    const resp = await axios.post(
      'http://localhost:3000/api/auth/signup',
      { 
        email: 'teste_api@vulnexus.com', 
        senha: 'senha123'
      },
      {
        headers: { "Content-Type": "application/json" },
        timeout: 10000,
      }
    );
    console.log('API Success:', resp.data);
  } catch (err) {
    if (err.response) {
      console.error('API Error Status:', err.response.status);
      console.error('API Error Data:', JSON.stringify(err.response.data, null, 2));
    } else {
      console.error('API Error Message:', err.message);
    }
  }
}

testApi();
