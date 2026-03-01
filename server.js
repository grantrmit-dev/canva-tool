/**
 * Canva Connect API Integration
 * Creates banners and reports via Canva's API with OAuth 2.0 + PKCE
 */
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Load credentials ──────────────────────────────────────────────────────────
const ENV_PATH = path.join(process.env.HOME, '.openclaw/canva/.env');
const env = {};
if (fs.existsSync(ENV_PATH)) {
  fs.readFileSync(ENV_PATH, 'utf8').split('\n').forEach(line => {
    const [k, ...v] = line.split('=');
    if (k && v.length) env[k.trim()] = v.join('=').trim();
  });
}

const CLIENT_ID     = env.CANVA_CLIENT_ID     || process.env.CANVA_CLIENT_ID;
const CLIENT_SECRET = env.CANVA_CLIENT_SECRET || process.env.CANVA_CLIENT_SECRET;
const REDIRECT_URI  = env.CANVA_REDIRECT_URI  || 'http://localhost:3456/oauth/callback';
const PORT          = process.env.PORT || 3456;
const TOKEN_FILE    = path.join(process.env.HOME, '.openclaw/canva/token.json');
const CANVA_API     = 'https://api.canva.com/rest/v1';

// ── PKCE helpers ──────────────────────────────────────────────────────────────
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}
function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ── Token storage ─────────────────────────────────────────────────────────────
function saveToken(token) {
  fs.mkdirSync(path.dirname(TOKEN_FILE), { recursive: true });
  fs.writeFileSync(TOKEN_FILE, JSON.stringify({ ...token, saved_at: Date.now() }), 'utf8');
  fs.chmodSync(TOKEN_FILE, 0o600);
}
function loadToken() {
  if (!fs.existsSync(TOKEN_FILE)) return null;
  return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
}

// ── Canva API client ──────────────────────────────────────────────────────────
async function canvaFetch(method, endpoint, body, token) {
  const res = await fetch(`${CANVA_API}${endpoint}`, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Canva API ${res.status}: ${text}`);
  return text ? JSON.parse(text) : {};
}

// ── Design operations ─────────────────────────────────────────────────────────
async function listDesigns(token) {
  return canvaFetch('GET', '/designs', null, token);
}

async function createDesign(token, { title, type = 'presentation' }) {
  // type: 'presentation' | 'doc' | 'social_media' | 'banner'
  return canvaFetch('POST', '/designs', {
    design_type: { type: 'preset', name: type },
    title,
  }, token);
}

async function exportDesign(token, designId, format = 'pdf') {
  // Start export job
  const job = await canvaFetch('POST', '/exports', {
    design_id: designId,
    format: { type: format },
  }, token);
  const jobId = job.job?.id;
  if (!jobId) throw new Error('Export job not created');

  // Poll until done
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const status = await canvaFetch('GET', `/exports/${jobId}`, null, token);
    if (status.job?.status === 'success') {
      return status.job?.urls || [];
    }
    if (status.job?.status === 'failed') throw new Error('Export failed');
  }
  throw new Error('Export timed out');
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

let pendingVerifier = null;

// ── Auth: start OAuth flow ────────────────────────────────────────────────────
app.get('/auth', (req, res) => {
  const verifier   = generateCodeVerifier();
  const challenge  = generateCodeChallenge(verifier);
  const state      = crypto.randomBytes(16).toString('hex');
  pendingVerifier  = verifier;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    scope:         'design:meta:read design:content:read design:content:write asset:read asset:write',
    state,
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  });

  res.redirect(`https://www.canva.com/api/oauth/authorize?${params}`);
});

// ── Auth: OAuth callback ──────────────────────────────────────────────────────
app.get('/oauth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`❌ OAuth error: ${error}`);
  if (!code) return res.send('❌ No code received.');

  try {
    const tokenRes = await fetch('https://api.canva.com/rest/v1/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  REDIRECT_URI,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: pendingVerifier,
      }),
    });
    const token = await tokenRes.json();
    if (token.error) throw new Error(token.error_description || token.error);
    saveToken(token);
    res.send(`
      <h2>✅ Canva connected successfully!</h2>
      <p>You can now close this tab and use the API.</p>
      <p>Try: <code>GET /designs</code> to list your designs.</p>
    `);
  } catch (err) {
    res.send(`❌ Token exchange failed: ${err.message}`);
  }
});

// ── API: list designs ─────────────────────────────────────────────────────────
app.get('/designs', async (req, res) => {
  const token = loadToken();
  if (!token) return res.status(401).json({ error: 'Not authenticated. Visit /auth first.' });
  try {
    const data = await listDesigns(token.access_token);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── API: create banner ────────────────────────────────────────────────────────
app.post('/banner', async (req, res) => {
  const token = loadToken();
  if (!token) return res.status(401).json({ error: 'Not authenticated. Visit /auth first.' });
  const { title = 'New Banner' } = req.body;
  try {
    const design = await createDesign(token.access_token, { title, type: 'presentation' });
    res.json({ message: 'Banner created', design });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── API: create report ────────────────────────────────────────────────────────
app.post('/report', async (req, res) => {
  const token = loadToken();
  if (!token) return res.status(401).json({ error: 'Not authenticated. Visit /auth first.' });
  const { title = 'New Report' } = req.body;
  try {
    const design = await createDesign(token.access_token, { title, type: 'doc' });
    res.json({ message: 'Report created', design });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── API: export design ────────────────────────────────────────────────────────
app.post('/export/:designId', async (req, res) => {
  const token = loadToken();
  if (!token) return res.status(401).json({ error: 'Not authenticated. Visit /auth first.' });
  const { format = 'pdf' } = req.body;
  try {
    const urls = await exportDesign(token.access_token, req.params.designId, format);
    res.json({ urls });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Status page ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const token = loadToken();
  const connected = !!token;
  res.send(`
    <!DOCTYPE html><html><head><title>Canva Integration</title>
    <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:0 20px;background:#f8fafc}
    h1{color:#7c3aed}.btn{display:inline-block;padding:12px 24px;background:#7c3aed;color:white;
    border-radius:8px;text-decoration:none;font-weight:600;margin:8px 4px}
    .btn.green{background:#059669}.card{background:white;border-radius:12px;padding:24px;
    margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}.status{font-size:1.1rem;padding:8px 0}</style>
    </head><body>
    <h1>🎨 Canva Integration</h1>
    <div class="card">
      <div class="status">${connected ? '✅ Connected to Canva' : '❌ Not connected yet'}</div>
      ${!connected ? '<a class="btn" href="/auth">Connect Canva Account</a>' : ''}
      ${connected  ? '<a class="btn green" href="/designs">List My Designs</a>' : ''}
    </div>
    <div class="card">
      <h3>Available endpoints</h3>
      <code>GET  /auth</code> — Start OAuth login<br><br>
      <code>GET  /designs</code> — List all designs<br><br>
      <code>POST /banner</code> — Create a banner <code>{"title":"My Banner"}</code><br><br>
      <code>POST /report</code> — Create a report <code>{"title":"My Report"}</code><br><br>
      <code>POST /export/:id</code> — Export design <code>{"format":"pdf"}</code>
    </div>
    </body></html>
  `);
});

app.listen(PORT, () => {
  console.log(`\n🎨 Canva Integration running at http://localhost:${PORT}`);
  console.log(`   → Authorize: http://localhost:${PORT}/auth`);
  console.log(`   → Status:    http://localhost:${PORT}/\n`);
});
