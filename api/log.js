export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const serviceAccountJson = process.env.GOOGLE_SERVICE_ACCOUNT;
  const sheetId = process.env.GOOGLE_SHEET_ID;

  if (!serviceAccountJson || !sheetId) {
    return res.status(500).json({ error: 'Missing environment variables' });
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(serviceAccountJson);
  } catch (e) {
    return res.status(500).json({ error: 'Invalid service account JSON' });
  }

  try {
    // Get OAuth token using JWT
    const token = await getAccessToken(serviceAccount);

    if (req.method === 'POST') {
      // LOG: Write a new row to the sheet
      const { agent, action, details, business, status } = req.body;
      const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
      const values = [[timestamp, agent || '', action || '', details || '', business || '5R TradeSuite AI', status || 'Complete']];

      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1!A:F:append?valueInputOption=RAW`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ values })
        }
      );

      if (!response.ok) {
        const err = await response.text();
        return res.status(500).json({ error: 'Failed to write to sheet', detail: err });
      }

      return res.status(200).json({ success: true, logged: { timestamp, agent, action, details, business, status } });

    } else if (req.method === 'GET') {
      // READ: Get the last 20 log entries for context
      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1!A:F`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      if (!response.ok) {
        const err = await response.text();
        return res.status(500).json({ error: 'Failed to read sheet', detail: err });
      }

      const data = await response.json();
      const rows = data.values || [];
      const headers = rows[0] || [];
      const entries = rows.slice(1).slice(-20).map(row => {
        const entry = {};
        headers.forEach((h, i) => entry[h] = row[i] || '');
        return entry;
      });

      return res.status(200).json({ success: true, entries, total: rows.length - 1 });
    }

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const privateKey = serviceAccount.private_key;
  const signature = await signRS256(signingInput, privateKey);
  const jwt = `${signingInput}.${signature}`;

  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  });

  const tokenData = await tokenResponse.json();
  if (!tokenData.access_token) {
    throw new Error('Failed to get access token: ' + JSON.stringify(tokenData));
  }
  return tokenData.access_token;
}

function base64url(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function signRS256(input, privateKeyPem) {
  const pemContents = privateKeyPem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const inputBytes = new TextEncoder().encode(input);
  const signatureBuffer = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, inputBytes);
  const signatureBytes = new Uint8Array(signatureBuffer);
  let binary = '';
  signatureBytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
