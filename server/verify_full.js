// const fetch = require('node-fetch'); // Using global fetch in Node.js 18+

const BASE_URL = 'http://localhost:5000/api';
const EMAIL = `user${Date.now()}@test.com`;
const PASSWORD = 'password123';

const PROFILE_DATA = {
    personal: { name: 'Test User', phone: '1234567890' },
    academics: { tenth_percentage: '90', twelfth_percentage: '85', cgpa: '9.0' },
    ids: { uid: 'U123', roll_number: 'R456' },
    links: { github: 'github.com/test', linkedin: 'linkedin.com/in/test' }
};

async function verifySystem() {
    console.log('--- Starting Full System Verification ---');

    try {
        // 1. Register
        console.log(`\n1. Registering ${EMAIL}...`);
        const regRes = await fetch(`${BASE_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: EMAIL, password: PASSWORD })
        });
        const regData = await regRes.json();
        console.log(`Status: ${regRes.status}`, regData);
        if (!regData.success) throw new Error('Registration failed');

        // 2. Login
        console.log(`\n2. Logging in...`);
        const loginRes = await fetch(`${BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: EMAIL, password: PASSWORD })
        });
        const loginData = await loginRes.json();
        console.log(`Status: ${loginRes.status}`, loginData);
        if (!loginData.success || !loginData.token) throw new Error('Login failed');
        
        const token = loginData.token;

        // 3. Get Initial Profile
        console.log(`\n3. Fetching Initial Profile...`);
        const p1Res = await fetch(`${BASE_URL}/profile`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const p1Data = await p1Res.json();
        console.log(`Status: ${p1Res.status}`, p1Data);

        // 4. Update Profile
        console.log(`\n4. Updating Profile...`);
        const updateRes = await fetch(`${BASE_URL}/profile`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ profile: PROFILE_DATA })
        });
        const updateData = await updateRes.json();
        console.log(`Status: ${updateRes.status}`, updateData);
        if (!updateData.success) throw new Error('Update failed');

        // 5. Verify Updated Profile
        console.log(`\n5. Verifying Updated Profile...`);
        const p2Res = await fetch(`${BASE_URL}/profile`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const p2Data = await p2Res.json();
        console.log(`Status: ${p2Res.status}`, JSON.stringify(p2Data.profile, null, 2));

        if (p2Data.profile.personal.name === PROFILE_DATA.personal.name) {
            console.log('\n✅ Verification SUCCESS: Profile updated correctly.');
        } else {
            console.error('\n❌ Verification FAILED: Profile data mismatch.');
        }

    } catch (err) {
        console.error('\n❌ Verification Error:', err.message);
    }
}

verifySystem();
