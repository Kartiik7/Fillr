// const fetch = require('node-fetch'); // Using global fetch in Node.js 18+

const BASE_URL = 'https://fillr-gqyp.onrender.com/api';
const EMAIL = `test${Date.now()}@example.com`;
const PASSWORD = 'password123';

async function testAuth() {
  console.log('--- Starting Auth Verification ---');

  // 1. Register
  console.log(`\n1. Registering user: ${EMAIL}`);
  try {
    const regRes = await fetch(`${BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    const regData = await regRes.json();
    console.log('Status:', regRes.status);
    console.log('Response:', regData);

    if (regRes.status !== 201) {
      console.error('Registration failed. Aborting.');
      return;
    }

    // 2. Login
    console.log(`\n2. Logging in...`);
    const loginRes = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    const loginData = await loginRes.json();
    console.log('Status:', loginRes.status);
    console.log('Response:', loginData);
    
    const token = loginData.token;
    if (!token) {
      console.error('Login failed (no token). Aborting.');
      return;
    }

    // 3. Get Profile
    console.log(`\n3. Getting Profile with Token...`);
    const profileRes = await fetch(`${BASE_URL}/profile`, {
      method: 'GET',
      headers: { 
        'Authorization': `Bearer ${token}` 
      },
    });
    const profileData = await profileRes.json();
    console.log('Status:', profileRes.status);
    console.log('Response:', profileData);

  } catch (err) {
    console.error('Verification Error:', err.message);
  }
}

// Check if running in environment where fetch is global (Node 18+)
if (typeof fetch === 'undefined') {
    // If not, we might need to enable experimental fetch or install node-fetch.
    // For this environment, we assume Node 18+ or standard compliant.
    console.log("Global fetch not available. Running in environment without it?");
} else {
    testAuth();
}
