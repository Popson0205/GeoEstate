// GeoEstate API Server — Production-ready build
// Loads credentials from .env file
const fs   = require('fs');
const path = require('path');
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const [k, ...v] = line.split('=');
    if (k && v.length) process.env[k.trim()] = v.join('=').trim();
  });
}

const http  = require('http');
const https = require('https');
const { Pool } = require('pg');

// ── Crash resilience ───────────────────────────────────────────────────────
// Crash resilience — keep process alive on unhandled errors.
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (process kept alive):', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (process kept alive):', reason);
});

// ── DB Pool ──────────────────────────────────────────────────────────────────
process.env.NODE_NO_WARNINGS = "1";
const db = new Pool({
  connectionString: process.env.SUPABASE_DB_URL, // Supabase: Settings → Database → URI (Transaction pooler, port 6543)
  ssl: { rejectUnauthorized: false }
});

// ── Config ───────────────────────────────────────────────────────────────────
const RESEND_API_KEY = process.env.SECRET_RESEND_API_KEY;
// ── Admin Auth Config ────────────────────────────────────────────────────────
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET     = process.env.JWT_SECRET;
if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !JWT_SECRET) {
  console.error('FATAL: ADMIN_EMAIL, ADMIN_PASSWORD, and JWT_SECRET must all be set in Railway environment variables.');
  process.exit(1);
}

// ── Minimal HS256 JWT (no external deps) ─────────────────────────────────────
const crypto = require('crypto');
function b64url(buf) { return buf.toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function jwtSign(payload, secret, expiresInHours = 8) {
  const header  = b64url(Buffer.from(JSON.stringify({ alg:'HS256', typ:'JWT' })));
  const body    = b64url(Buffer.from(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + expiresInHours * 3600 })));
  const sig     = b64url(crypto.createHmac('sha256', secret).update(header + '.' + body).digest());
  return header + '.' + body + '.' + sig;
}
function jwtVerify(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = b64url(crypto.createHmac('sha256', secret).update(header + '.' + body).digest());
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString());
    if (payload.exp < Math.floor(Date.now()/1000)) return null; // expired
    return payload;
  } catch(e) { return null; }
}

// ── Sales Team Config ──────────────────────────────────────────────────────
const SALES_TEAM = [
  {
    name:      'Majekodunmi Lateefat',
    title:     'Sales Manager',
    email:     'mlateefat95@gmail.com',
    phone:     '+2348133343645',
    whatsapp:  '2348133343645'
  },
  {
    name:      'Adesina Faridat Adenike',
    title:     'Sales Manager',
    email:     'faridat3008@gmail.com',
    phone:     '+2349131916831',
    whatsapp:  '2349131916831'
  }
];
const FROM_EMAIL     = 'GeoEstate <noreply@geoestate.com.ng>';
const sseClients     = new Set(); // for Server-Sent Events

// ── OTP store (Postgres-backed) ──────────────────────────────────────────────
// NOTE: OTP codes are stored in Postgres so they survive service restarts.
// gone away. Storing in Postgres makes it durable across instances.
async function otpSet(key, code, ttlMs) {
  const expires = new Date(Date.now() + ttlMs);
  await db.query(
    `INSERT INTO otp_codes (key, code, expires, attempts)
     VALUES ($1,$2,$3,0)
     ON CONFLICT (key) DO UPDATE SET code=$2, expires=$3, attempts=0, created_at=NOW()`,
    [key, code, expires]
  );
}

async function otpGet(key) {
  const r = await db.query('SELECT code, expires, attempts FROM otp_codes WHERE key=$1', [key]);
  if (!r.rows.length) return null;
  const row = r.rows[0];
  return { code: row.code, expires: new Date(row.expires).getTime(), attempts: row.attempts };
}

async function otpIncrementAttempts(key) {
  await db.query('UPDATE otp_codes SET attempts = attempts + 1 WHERE key=$1', [key]);
}

async function otpDelete(key) {
  await db.query('DELETE FROM otp_codes WHERE key=$1', [key]);
}

// ── SSE Broadcast ─────────────────────────────────────────────────────────────
// NOTE: sseClients is per-process. Multiple Railway replicas = use Railway's
// serverless instance. A write from one instance (e.g. an admin saving a
// property) cannot reach a browser whose /events connection landed on a
// different instance — there's no shared memory between them. The frontend's
// 5s auto-reconnect (geo-api.js) keeps the connection alive in practice, but
// Redis pub/sub for true fan-out. Single replica works fine for launch.
// single always-on process. A managed pub/sub (e.g. Pusher/Ably) or polling
// would be needed for guaranteed real-time sync on serverless hosting.
function broadcast(eventName, data) {
  const msg = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.write(msg); } catch(e) { sseClients.delete(client); }
  }
}

// ── Auth Middleware ───────────────────────────────────────────────────────────
function requireAdmin(req, res) {
  const auth  = req.headers['authorization'] || req.headers['x-admin-token'] || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  const payload = jwtVerify(token, JWT_SECRET);
  if (!payload || payload.role !== 'admin') {
    json(res, 401, { error: 'Unauthorized — please log in again' });
    return false;
  }
  return payload;
}

function requireOwner(req, res) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token || !token.startsWith('owner:')) {
    json(res, 401, { error: 'Owner authentication required' });
    return null;
  }
  // Token format: owner:<userId>:<timestamp>
  const parts = token.split(':');
  if (parts.length < 3) { json(res, 401, { error: 'Invalid token format' }); return null; }
  // Validate timestamp — reject tokens older than 24 hours
  const timestamp = parseInt(parts[parts.length - 1]);
  if (!timestamp || isNaN(timestamp) || Date.now() - timestamp > 24 * 60 * 60 * 1000) {
    json(res, 401, { error: 'Token expired. Please log in again.' });
    return null;
  }
  // parts[0]='owner', parts[last]=timestamp, middle = userId
  parts.shift(); // remove 'owner'
  parts.pop();   // remove timestamp
  const userId = parts.join(':');
  if (!userId || userId.length < 3) { json(res, 401, { error: 'Invalid token' }); return null; }
  return userId;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function json(res, code, data) {
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Token'
  });
  res.end(JSON.stringify(data));
}

function sendEmail(to, subject, html) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ from: FROM_EMAIL, to: [to], subject, html });
    const req  = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + RESEND_API_KEY,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const p = JSON.parse(d);
        if (res.statusCode === 200 || res.statusCode === 201) resolve(p);
        else reject(new Error(p.message || 'Send failed'));
      });
    });
    req.on('error', reject); req.write(body); req.end();
  });
}

function otpEmail(code, name, purpose) {
  const text = purpose === 'register' ? 'complete your GeoEstate registration' : 'verify your identity';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:480px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:32px 40px;text-align:center">
  <div style="font-size:28px;margin-bottom:8px">📍</div>
  <div style="color:#fff;font-size:22px;font-weight:800">GeoEstate</div>
  <div style="color:rgba(255,255,255,.6);font-size:13px;margin-top:4px">Verified Real Estate · Nigeria</div>
</td></tr>
<tr><td style="padding:40px">
  <div style="font-size:16px;font-weight:700;color:#111827;margin-bottom:8px">Hi${name ? ' ' + name : ''},</div>
  <div style="font-size:14px;color:#6b7280;line-height:1.6;margin-bottom:28px">Use the code below to ${text}. Expires in <strong>10 minutes</strong>.</div>
  <div style="background:#f0fdf4;border:2px dashed #86efac;border-radius:12px;padding:24px;text-align:center;margin-bottom:28px">
    <div style="font-size:11px;font-weight:700;color:#15803d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px">Verification Code</div>
    <div style="font-size:42px;font-weight:900;letter-spacing:.3em;color:#0d3d22;font-family:monospace">${code}</div>
    <div style="font-size:12px;color:#6b7280;margin-top:10px">Valid 10 min · Do not share</div>
  </div>
  <div style="background:#fffbeb;border-radius:8px;padding:14px 16px;font-size:13px;color:#92400e">🔒 GeoEstate will never ask for this code by phone or message.</div>
</td></tr>
<tr><td style="background:#f9fafb;padding:20px 40px;border-top:1px solid #f3f4f6;text-align:center">
  <div style="font-size:12px;color:#9ca3af">GeoEstate · Popson Geospatial Services · Nigeria<br>
  <a href="mailto:admin@geoestate.com.ng" style="color:#1a6b3c">admin@geoestate.com.ng</a></div>
</td></tr>
</table></td></tr></table></body></html>`;
}

function adminAlertEmail(user) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:520px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:24px 32px">
  <div style="color:#fff;font-size:18px;font-weight:800">📍 GeoEstate Admin Alert</div>
  <div style="color:rgba(255,255,255,.65);font-size:13px;margin-top:4px">New registration — identity review required</div>
</td></tr>
<tr><td style="padding:32px">
  <div style="background:#f0fdf4;border-radius:10px;padding:20px;margin-bottom:20px">
    <table style="width:100%;font-size:14px;border-collapse:collapse">
      <tr><td style="color:#6b7280;padding:4px 0;width:40%">Name</td><td style="font-weight:700">${user.fname} ${user.lname}</td></tr>
      <tr><td style="color:#6b7280;padding:4px 0">Email</td><td>${user.email}</td></tr>
      <tr><td style="color:#6b7280;padding:4px 0">Phone</td><td>${user.phone}</td></tr>
      <tr><td style="color:#6b7280;padding:4px 0">Role</td><td><span style="background:#eff6ff;color:#1e40af;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700">${user.role === 'owner' ? '🏠 Property Owner' : '🔑 Renter/Buyer'}</span></td></tr>
      <tr><td style="color:#6b7280;padding:4px 0">Ref ID</td><td style="font-family:monospace;font-size:12px">${user.id}</td></tr>
    </table>
  </div>
  <div style="background:#fffbeb;border-radius:8px;padding:12px 16px;font-size:13px;color:#92400e;margin-bottom:20px">⏱️ SLA: Identity review within <strong>48 hours</strong>.</div>
</td></tr>
</table></td></tr></table></body></html>`;
}

function enquiryEmail(enq, property) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:520px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:24px 32px">
  <div style="color:#fff;font-size:18px;font-weight:800">📍 New Property Enquiry</div>
  <div style="color:rgba(255,255,255,.65);font-size:13px;margin-top:4px">${property || 'Property interest received'}</div>
</td></tr>
<tr><td style="padding:32px">
  <p style="color:#374151;font-size:14px">A prospective tenant/buyer has expressed interest:</p>
  <table style="width:100%;font-size:14px;border-collapse:collapse;background:#f0fdf4;border-radius:8px;padding:12px">
    <tr><td style="padding:6px 12px;color:#6b7280">Name</td><td style="padding:6px 12px;font-weight:700">${enq.name}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">Email</td><td style="padding:6px 12px">${enq.email}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">Phone</td><td style="padding:6px 12px">${enq.phone || '—'}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">Message</td><td style="padding:6px 12px">${enq.message || '—'}</td></tr>
  </table>
</td></tr>
</table></td></tr></table></body></html>`;
}

// ── Sales alert email template ───────────────────────────────────────────────
function salesAlertEmail(enq, propertyTitle, salesPerson) {
  const waMsg = encodeURIComponent(
    'Hi ' + enq.name + ', I\'m ' + salesPerson.name + ' from GeoEstate Sales. I saw your enquiry about "' + propertyTitle + '" (ID: ' + (enq.property_id||'N/A') + '). I\'d love to help you with this. When is a good time to talk?'
  );
  const waLink = 'https://wa.me/' + enq.phone.replace(/[^0-9]/g,'') + '?text=' + waMsg;
  const waLinkSelf = 'https://wa.me/' + salesPerson.whatsapp + '?text=' + encodeURIComponent('New lead: ' + enq.name + ' (' + enq.phone + ') enquired about "' + propertyTitle + '"');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:540px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:24px 32px">
  <div style="color:#fff;font-size:20px;font-weight:800">🔔 New Property Enquiry</div>
  <div style="color:rgba(255,255,255,.7);font-size:13px;margin-top:4px">Action required — respond within 1 hour</div>
</td></tr>
<tr><td style="padding:28px 32px">
  <div style="background:#f0fdf4;border-radius:10px;padding:16px;margin-bottom:20px">
    <div style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Property</div>
    <div style="font-size:16px;font-weight:800;color:#0d3d22">${propertyTitle}</div>
  </div>
  <div style="background:#f9fafb;border-radius:10px;padding:16px;margin-bottom:20px">
    <div style="font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px">Lead Details</div>
    <table style="width:100%;font-size:14px;border-collapse:collapse">
      <tr><td style="padding:5px 0;color:#6b7280;width:80px">Name</td><td style="padding:5px 0;font-weight:700">${enq.name}</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280">Email</td><td style="padding:5px 0">${enq.email}</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280">Phone</td><td style="padding:5px 0;font-weight:700">${enq.phone || '—'}</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280">Message</td><td style="padding:5px 0;font-style:italic">${enq.message || '—'}</td></tr>
    </table>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">
    <a href="${waLink}" style="display:inline-block;background:#25D366;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:14px">💬 WhatsApp Lead</a>
    <a href="tel:${enq.phone}" style="display:inline-block;background:#1a6b3c;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:14px">📞 Call Lead</a>
    <a href="mailto:${enq.email}" style="display:inline-block;background:#f3f4f6;color:#111;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:700;font-size:14px">✉️ Email Lead</a>
  </div>
  <div style="font-size:12px;color:#9ca3af;border-top:1px solid #f3f4f6;padding-top:16px">
    This alert was sent to you as ${salesPerson.name} (${salesPerson.title}) on the GeoEstate Sales Team.<br>
    Log into the <a href="https://www.geoestate.com.ng" style="color:#1a6b3c">GeoEstate Admin Dashboard</a> to manage this enquiry.
  </div>
</td></tr>
</table></td></tr></table></body></html>`;
}

async function logActivity(msg) {
  try { await db.query('INSERT INTO activity_log (message) VALUES ($1)', [msg]); } catch(e) {}
  broadcast('activity', { message: msg, time: new Date().toISOString() });
}

// ══════════════════════════════════════════════════════════════
// PHASE 1 — ROUTE HANDLERS
// ══════════════════════════════════════════════════════════════

async function handleSendOTP(data, res) {
  const { email, name, purpose } = data;
  if (!email || !email.includes('@')) return json(res, 400, { error: 'Valid email required' });
  const code = generateOTP();

  // Step 1: Save OTP to DB — this MUST happen regardless of email outcome
  try {
    await otpSet(email.toLowerCase(), code, 10 * 60 * 1000);
  } catch(dbErr) {
    console.error('OTP DB save failed:', dbErr.message);
    return json(res, 500, { error: 'Could not save verification code. Please try again.' });
  }

  // Step 2: Send email — non-fatal. If Resend isn't configured or domain unverified,
  // return devCode so the user/developer can complete verification without email.
  const hasResend = !!RESEND_API_KEY;
  if (!hasResend) {
    console.warn('SECRET_RESEND_API_KEY not set — returning devCode for testing');
    return json(res, 200, { success: true, message: 'Code generated (no email key)', testMode: true, devCode: code });
  }

  try {
    await sendEmail(email, 'GeoEstate — Your Code: ' + code, otpEmail(code, name || '', purpose || 'register'));
    json(res, 200, { success: true, message: 'Code sent to ' + email });
  } catch(emailErr) {
    // Email failed (unverified domain, bounce, etc.) — code is in DB, surface devCode
    console.warn('Email send failed:', emailErr.message, '— returning devCode fallback');
    json(res, 200, {
      success: true,
      message: 'Email delivery issue — use code below',
      testMode: true,
      devCode: code,
      emailError: emailErr.message
    });
  }
}

async function handleVerifyOTP(data, res) {
  const { email, code } = data;
  if (!email || !code) return json(res, 400, { error: 'Email and code required' });
  try {
    const key = email.toLowerCase();
    const record = await otpGet(key);
    if (!record) return json(res, 400, { error: 'No code found. Request a new one.' });
    if (Date.now() > record.expires) { await otpDelete(key); return json(res, 400, { error: 'Code expired.' }); }
    if (record.attempts > 5) { await otpDelete(key); return json(res, 429, { error: 'Too many attempts. Request a new code.' }); }
    if (code !== record.code) {
      await otpIncrementAttempts(key);
      return json(res, 400, { error: 'Incorrect code. ' + (5 - record.attempts - 1) + ' attempt(s) remaining.' });
    }
    await otpDelete(key);
    json(res, 200, { success: true, message: 'Email verified' });
  } catch(e) {
    json(res, 500, { error: e.message });
  }
}


// ── User Login — POST /user/login ────────────────────────────────────────────
// Validates email + password against registrations table in Neon.
// Password is stored as base64(password) in the reg payload (same as frontend btoa).
// Returns the user record on success.
async function handleUserLogin(data, res) {
  const { email, password } = data;
  if (!email || !password) return json(res, 400, { error: 'Email and password required' });
  try {
    const r = await db.query(
      'SELECT id, fname, lname, email, phone, role, status, is_verified, pass_hash FROM registrations WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    if (!r.rows.length) return json(res, 401, { error: 'No account found with this email. Please register first.' });
    const user = r.rows[0];
    // Password stored as btoa(password) by frontend — compare base64
    const expected = Buffer.from(password).toString('base64');
    if (user.pass_hash) {
      if (user.pass_hash !== expected) {
        return json(res, 401, { error: 'Incorrect password. Please try again.' });
      }
    } else {
      // No password stored yet — accept login and save hash for next time
      await db.query(
        'UPDATE registrations SET pass_hash = $1, updated_at = NOW() WHERE id = $2',
        [expected, user.id]
      ).catch(e => console.warn('pass_hash update failed:', e.message));
    }
    json(res, 200, {
      success: true,
      user: {
        id:       user.id,
        fname:    user.fname,
        lname:    user.lname,
        email:    user.email,
        phone:    user.phone,
        role:     user.role,
        verified: user.is_verified || false
      }
    });
  } catch(e) {
    console.error('User login error:', e.message);
    json(res, 500, { error: 'Login failed. Please try again.' });
  }
}

async function handleRegister(data, res) {
  const { fname, lname, email, phone, role, id, registeredAt } = data;
  if (!email || !fname) return json(res, 400, { error: 'Name and email required' });
  // pass is sent as btoa(password) from frontend doRegister()
  const pass_hash = data.pass || null;
  const { dob, gender, occupation, employer, state: regState, lga: regLga, address: regAddress, next_of_kin, next_of_kin_rel, next_of_kin_phone, nin } = data; // FIX 2: added nin
  try {
    const exists = await db.query('SELECT id FROM registrations WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length) return json(res, 200, { success: true, message: 'Already registered' });
    const subId = id || ('USR-' + Date.now());
    // Try full insert with all extended fields, fall back to minimal
    try {
      const { photo_url, id_doc_url, other_doc_url } = data;
      await db.query(
        `INSERT INTO registrations (id,fname,lname,email,phone,role,type,status,submitted,registered_at,initials,dob,gender,occupation,employer,state,lga,address,next_of_kin,next_of_kin_rel,next_of_kin_phone,nin,photo_url,id_doc_url,other_doc_url,pass_hash) // FIX 2: nin column added
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
        [subId, fname, lname, email.toLowerCase(), phone||'', role||'renter', role||'renter',
         new Date().toLocaleString('en-NG'), registeredAt||new Date().toISOString(),
         (fname[0]||'')+(lname[0]||''),
         dob||'—', gender||'—', occupation||'—', employer||'—',
         regState||'—', regLga||'—', regAddress||'—',
         next_of_kin||'—', next_of_kin_rel||'—', next_of_kin_phone||'—',
         nin||'', // FIX: nin now saved
         photo_url||null, id_doc_url||null, other_doc_url||null, pass_hash||null]
      );
    } catch(e1) {
      // Fallback: minimal insert if extended columns missing
      await db.query(
        `INSERT INTO registrations (id,fname,lname,email,phone,role,type,status,submitted,registered_at,initials)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$10)`,
        [subId, fname, lname, email.toLowerCase(), phone||'', role||'renter', role||'renter',
         new Date().toLocaleString('en-NG'), registeredAt||new Date().toISOString(),
         (fname[0]||'')+(lname[0]||'')]
      );
    }
    await logActivity('New registration: ' + fname + ' ' + lname + ' (' + (role==='owner'?'Owner':'Renter') + ')');
    sendEmail('admin@geoestate.com.ng', '🆕 New Registration: ' + fname + ' ' + lname, adminAlertEmail({fname,lname,email,phone,role,id:subId}))
      .catch(e => console.warn('Admin alert failed:', e.message));
    json(res, 200, { success: true, submissionId: subId });
  } catch(e) {
    console.error('Register error:', e.message);
    json(res, 500, { error: e.message });
  }
}

// ── Public Properties (with type filter) ──
async function handlePublicProperties(urlFull, res) {
  try {
    const params = new URL('http://x' + urlFull).searchParams;
    const typeFilter = params.get('type');
    const state  = params.get('state');
    const search = params.get('q');

    let query = "SELECT id, title, owner, owner_id, type, COALESCE(listing_type, type, 'rent') as listing_type, status, price, state, lga, address, img, created_at FROM properties WHERE status='live'";
    const args = [];

    if (typeFilter) {
      args.push(typeFilter);
      query += " AND (COALESCE(listing_type, type, 'rent') = $" + args.length + ")";
    }
    if (state) {
      args.push('%' + state + '%');
      query += ' AND state ILIKE $' + args.length;
    }
    if (search) {
      args.push('%' + search + '%');
      query += ' AND (title ILIKE $' + args.length + ' OR address ILIKE $' + args.length + ' OR lga ILIKE $' + args.length + ')';
    }
    query += ' ORDER BY created_at DESC';

    let result;
    try {
      result = await db.query(query, args);
    } catch(e1) {
      // listing_type column missing — use type only
      let q2 = "SELECT id, title, owner, type, type as listing_type, status, price, state, lga, address, img, created_at FROM properties WHERE status='live'";
      const args2 = [];
      if (typeFilter) { args2.push(typeFilter); q2 += ' AND type=$' + args2.length; }
      if (state) { args2.push('%'+state+'%'); q2 += ' AND state ILIKE $' + args2.length; }
      q2 += ' ORDER BY created_at DESC';
      result = await db.query(q2, args2);
    }
    json(res, 200, { success: true, count: result.rows.length, properties: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}


async function handlePublicPropertyById(id, res) {
  try {
    let prop;
    try {
      const r = await db.query(
        "SELECT id,title,owner,owner_id,type,COALESCE(listing_type,type,'rent') as listing_type,status,price,COALESCE(monthly_rent,NULL) as monthly_rent,COALESCE(sale_price,NULL) as sale_price,COALESCE(lease_price,NULL) as lease_price,state,lga,address,img,COALESCE(images,'[]'::jsonb) as images,COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,COALESCE(description,'') as description,COALESCE(amenities,'[]'::jsonb) as amenities,notes,created_at FROM properties WHERE id=$1",
        [id]
      );
      if (!r.rows.length) return json(res, 404, { error: 'Property not found' });
      prop = r.rows[0];
    } catch(e1) {
      const r = await db.query("SELECT id,title,owner,owner_id,type,type as listing_type,status,price,state,lga,address,img,COALESCE(description,'') as description,COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,notes,created_at FROM properties WHERE id=$1", [id]);
      if (!r.rows.length) return json(res, 404, { error: 'Property not found' });
      prop = r.rows[0];
    }
    // Try units
    try {
      const ur = await db.query("SELECT id,unit_label,unit_type,floor_level,capacity,monthly_price,status,occupied_since,lease_end FROM property_units WHERE property_id=$1 ORDER BY unit_label", [id]);
      prop.units = ur.rows;
    } catch(ue) { prop.units = []; }
    json(res, 200, { success: true, property: prop });
  } catch(e) { json(res, 500, { error: e.message }); }
}


async function handleGetRegistrations(url, res) {
  try {
    const since = new URL('http://x' + url).searchParams.get('since');
    let q = 'SELECT * FROM registrations ORDER BY created_at DESC';
    const params = [];
    if (since) { q = 'SELECT * FROM registrations WHERE created_at > $1 ORDER BY created_at DESC'; params.push(new Date(parseInt(since))); }
    const result = await db.query(q, params);
    const rows = result.rows.map(r => ({
      id: r.id, name: r.fname + ' ' + r.lname,
      fname: r.fname, lname: r.lname, email: r.email, phone: r.phone,
      role: r.role, type: r.type, status: r.status,
      submitted: r.submitted, registeredAt: r.registered_at,
      slaH: r.sla_h || 0, reviewer: r.reviewer || 'Unassigned',
      initials: r.initials || (r.fname[0]+r.lname[0]),
      dob: r.dob||'—', gender: r.gender||'—', occupation: r.occupation||'—',
      employer: r.employer||'—', state: r.state||'—', lga: r.lga||'—',
      address: r.address||'—', nin: r.nin||'***-***-****',
      doc: r.doc||'Pending upload', notes: r.notes||'',
      nextOfKin: r.next_of_kin||'—', nextOfKinRel: r.next_of_kin_rel||'—',
      nextOfKinPhone: r.next_of_kin_phone||'—',
      isVerified: r.is_verified||false
    }));
    json(res, 200, { success: true, count: rows.length, registrations: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetProperties(res) {
  try {
    // Use safe column list that works with both old and new schema
    const result = await db.query(`
      SELECT id, title, owner, owner_id, type,
        COALESCE(listing_type, type, 'rent') as listing_type,
        status, price,
        COALESCE(monthly_rent, CASE WHEN type='rent' THEN NULL ELSE NULL END) as monthly_rent,
        COALESCE(sale_price, NULL) as sale_price,
        COALESCE(lease_price, NULL) as lease_price,
        state, lga, address, img,
        COALESCE(images, '[]'::jsonb) as images,
        COALESCE(bedrooms, NULL) as bedrooms,
        COALESCE(bathrooms, NULL) as bathrooms,
        COALESCE(size_sqm, NULL) as size_sqm,
        COALESCE(description, '') as description,
        COALESCE(amenities, '[]'::jsonb) as amenities,
        notes, submitted, created_at, updated_at
      FROM properties ORDER BY created_at DESC
    `);
    json(res, 200, { success: true, count: result.rows.length, properties: result.rows });
  } catch(e) {
    // Fallback: minimal safe query if new columns don't exist yet
    try {
      const r2 = await db.query('SELECT id,title,owner,type,type as listing_type,status,price,state,lga,address,img,notes,submitted,created_at FROM properties ORDER BY created_at DESC');
      json(res, 200, { success: true, count: r2.rows.length, properties: r2.rows });
    } catch(e2) { json(res, 500, { error: e2.message }); }
  }
}

async function handleGetTeam(res) {
  try {
    const result = await db.query('SELECT * FROM team_members ORDER BY id');
    json(res, 200, { success: true, team: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetLawyers(res) {
  try {
    const result = await db.query('SELECT * FROM lawyers ORDER BY id');
    json(res, 200, { success: true, lawyers: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetTransactions(res) {
  try {
    const result = await db.query('SELECT * FROM transactions ORDER BY created_at DESC');
    json(res, 200, { success: true, transactions: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetTenancies(res) {
  try {
    const result = await db.query(`
      SELECT t.*,
        CASE WHEN t.end_date <= CURRENT_DATE + INTERVAL '30 days' AND t.status='active' THEN true ELSE false END as expiring_soon
      FROM tenancies t ORDER BY end_date ASC
    `);
    const rows = result.rows.map(r => ({
      id: r.id, ref: r.ref, type: r.type, property: r.property,
      propertyId: r.property_id, unitId: r.unit_id,
      tenant: r.tenant, tenantId: r.tenant_id, phone: r.phone, owner: r.owner,
      amount: r.amount, start: r.start_date, end: r.end_date,
      status: r.status, packingOutDate: r.packing_out_date,
      renewedAt: r.renewed_at, vacatedAt: r.vacated_at, notes: r.notes,
      expiringSoon: r.expiring_soon
    }));
    json(res, 200, { success: true, tenancies: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleAdminUpdate(url, data, res) {
  const regMatch = url.match(/^\/admin\/registration\/([^/]+)$/);
  if (regMatch) {
    const id = regMatch[1];
    const { status, reviewer, notes } = data;
    try {
      await db.query(
        'UPDATE registrations SET status=$1, reviewer=$2, notes=$3, updated_at=NOW() WHERE id=$4',
        [status, reviewer||'Admin', notes||'', id]
      );
      // If approved as owner, ensure owner capability
      if (status === 'approved') {
        try {
          await db.query('UPDATE registrations SET is_verified=true WHERE id=$1 AND role=$2', [id, 'owner']);
        } catch(verifyErr) {
          // is_verified column may not exist yet — add it and retry
          try {
            await db.query("ALTER TABLE registrations ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE");
            await db.query("ALTER TABLE registrations ADD COLUMN IF NOT EXISTS owner_since TIMESTAMPTZ");
            await db.query('UPDATE registrations SET is_verified=true WHERE id=$1 AND role=$2', [id, 'owner']);
          } catch(e2) { console.warn('is_verified column fix failed:', e2.message); }
        }
      }
      await logActivity('Registration ' + status + ': ' + id);
      broadcast('registration_updated', { id, status });
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  const propMatch = url.match(/^\/admin\/property\/([^/]+)$/);
  if (propMatch) {
    const id = propMatch[1];
    try {
      const allowed = ['title','owner','listing_type','type','status','price','monthly_rent','sale_price','lease_price','state','lga','address','img','images','bedrooms','bathrooms','size_sqm','description','amenities','notes','lawyer_assigned','geo'];
      const fields = Object.entries(data).filter(([k]) => allowed.includes(k));
      if (!fields.length) return json(res, 400, { error: 'No valid fields' });
      const sets = fields.map(([k],i) => `${k}=$${i+2}`).join(',');
      await db.query(`UPDATE properties SET ${sets},updated_at=NOW() WHERE id=$1`, [id, ...fields.map(([,v])=>v)]);
      await logActivity('Property updated: ' + id);
      broadcast('property_updated', { id });
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  const tenMatch = url.match(/^\/admin\/tenancy\/([^/]+)$/);
  if (tenMatch) {
    const id = tenMatch[1];
    const { status, packing_out_date, renewed_at, vacated_at, notes } = data;
    try {
      await db.query(
        'UPDATE tenancies SET status=$1, packing_out_date=$2, renewed_at=$3, vacated_at=$4, notes=COALESCE($5,notes), updated_at=NOW() WHERE id=$6',
        [status, packing_out_date||null, renewed_at||null, vacated_at||null, notes||null, id]
      );
      broadcast('tenancy_updated', { id, status });
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  const enqMatch = url.match(/^\/admin\/enquiry\/([^/]+)$/);
  if (enqMatch) {
    const id = enqMatch[1];
    const { status, notes, assigned_to } = data;
    try {
      await db.query(
        'UPDATE enquiries SET status=COALESCE($1,status), notes=COALESCE($2,notes), assigned_to=COALESCE($3,assigned_to) WHERE id=$4',
        [status||null, notes||null, assigned_to||null, id]
      );
      await logActivity('Enquiry ' + id + ' updated → ' + (status||'no status change'));
      broadcast('enquiry_updated', { id, status });
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }


  json(res, 404, { error: 'Unknown admin update endpoint' });
}

async function handleSaveProperty(data, res) {
  const { id, title, owner, owner_id, listing_type, type, status, price, monthly_rent, sale_price, lease_price, state, lga, address, img, images, bedrooms, bathrooms, size_sqm, description, amenities, notes } = data;
  if (!title) return json(res, 400, { error: 'Title required' });
  const propId = id || ('PROP-' + Date.now());
  const lt = listing_type || type || 'rent';
  try {
    // Try new schema first, fall back to basic insert if columns missing
    try {
      await db.query(
        `INSERT INTO properties (id,title,owner,owner_id,type,status,price,state,lga,address,img,notes,submitted)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (id) DO UPDATE SET title=$2,owner=$3,type=$5,status=$6,price=$7,state=$8,lga=$9,address=$10,img=$11,notes=$12,updated_at=NOW()`,
        [propId,title,owner||'',owner_id||null,lt,status||'pending',price||'',state||'',lga||'',address||'',img||'',notes||'',new Date().toLocaleString('en-NG')]
      );
      // Try to update new columns separately (safe if they don't exist yet)
      await db.query(
        `UPDATE properties SET listing_type=$1,monthly_rent=$2,sale_price=$3,lease_price=$4,images=$5,bedrooms=$6,bathrooms=$7,size_sqm=$8,description=$9,amenities=$10 WHERE id=$11`,
        [lt,monthly_rent||null,sale_price||null,lease_price||null,JSON.stringify(images||[]),bedrooms||null,bathrooms||null,size_sqm||null,description||'',JSON.stringify(amenities||[]),propId]
      ).catch(()=>{}); // Silent fail if columns missing — run schema.sql to enable
    } catch(e2) { throw e2; }
    await logActivity((id ? 'Property updated: ' : 'Property added: ') + title);
    broadcast('property_created', { id: propId, title, listing_type: lt });
    json(res, 200, { success: true, propertyId: propId });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSaveLawyer(data, res) {
  const { id, name, bar, spec, state, email, phone, bio, photo, status } = data;
  if (!name) return json(res, 400, { error: 'Name required' });
  try {
    if (id) {
      await db.query('UPDATE lawyers SET name=$1,bar=$2,spec=$3,state=$4,email=$5,phone=$6,bio=$7,photo=$8,status=$9 WHERE id=$10',
        [name,bar||'',spec||'',state||'',email||'',phone||'',bio||'',photo||'',status||'active',id]);
    } else {
      await db.query('INSERT INTO lawyers (name,bar,spec,state,email,phone,bio,photo,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [name,bar||'',spec||'',state||'',email||'',phone||'',bio||'',photo||'',status||'active']);
    }
    await logActivity((id?'Lawyer updated: ':'Lawyer added: ') + name);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSaveTeamMember(data, res) {
  const { id, name, role, phone, email, photo, status } = data;
  if (!name) return json(res, 400, { error: 'Name required' });
  try {
    if (id) {
      await db.query('UPDATE team_members SET name=$1,role=$2,phone=$3,email=$4,photo=$5,status=$6 WHERE id=$7',
        [name,role||'',phone||'',email||'',photo||'',status||'active',id]);
    } else {
      await db.query('INSERT INTO team_members (name,role,phone,email,photo,status) VALUES ($1,$2,$3,$4,$5,$6)',
        [name,role||'',phone||'',email||'',photo||'',status||'active']);
    }
    await logActivity((id?'Team updated: ':'Team member added: ') + name);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSaveTenancy(data, res) {
  const { ref, type, property, property_id, unit_id, tenant, tenant_id, phone, owner, amount, start, end, notes } = data;
  if (!property || !tenant || !end) return json(res, 400, { error: 'Property, tenant and end date required' });
  try {
    await db.query(
      `INSERT INTO tenancies (ref,type,property,property_id,unit_id,tenant,tenant_id,phone,owner,amount,start_date,end_date,notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (ref) DO NOTHING`,
      [ref||('TEN-'+Date.now()),type||'rent',property,property_id||null,unit_id||null,tenant,tenant_id||null,phone||'',owner||'',amount||0,start,end,notes||'']
    );
    // If unit_id provided, mark unit as occupied
    if (unit_id) {
      await db.query("UPDATE property_units SET status='occupied', current_tenant_id=$1, occupied_since=$2, lease_end=$3 WHERE id=$4",
        [tenant_id||null, start, end, unit_id]);
    }
    await logActivity('Tenancy added: ' + ref + ' — ' + property);
    broadcast('tenancy_created', { property });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteTeamMember(id, res) {
  try { await db.query('DELETE FROM team_members WHERE id=$1', [id]); json(res, 200, { success: true }); }
  catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteLawyer(id, res) {
  try { await db.query('DELETE FROM lawyers WHERE id=$1', [id]); json(res, 200, { success: true }); }
  catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteProperty(id, res) {
  try {
    await db.query("UPDATE properties SET status='rejected', updated_at=NOW() WHERE id=$1", [id]);
    broadcast('property_updated', { id, status: 'rejected' });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteTenancy(id, res) {
  try { await db.query('DELETE FROM tenancies WHERE id=$1', [id]); json(res, 200, { success: true }); }
  catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetActivityLog(res) {
  try {
    const result = await db.query('SELECT * FROM activity_log ORDER BY logged_at DESC LIMIT 100');
    json(res, 200, { success: true, log: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetDisputes(res) {
  try {
    const r = await db.query('SELECT * FROM disputes ORDER BY created_at DESC');
    json(res, 200, { success: true, disputes: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSubmitDispute(data, res) {
  const { title, property, complainant, complainantId, respondent, respondentId, amount, description, severity } = data;
  if (!title || !complainant) return json(res, 400, { error: 'Title and complainant required' });
  const id = 'DIS-' + Date.now();
  try {
    await db.query(
      'INSERT INTO disputes (id,title,property,complainant,complainant_id,respondent,respondent_id,amount,description,severity,filed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [id, title, property||'', complainant, complainantId||'', respondent||'', respondentId||'', amount||'0', description||'', severity||'medium', new Date().toLocaleString('en-NG')]
    );
    await logActivity('Dispute filed: ' + title + ' by ' + complainant);
    json(res, 200, { success: true, disputeId: id });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleUpdateDispute(id, data, res) {
  const { status, lawyerAssigned, npfFiled, notes } = data;
  try {
    // Try full update first, fall back without notes column if missing
    try {
      await db.query('UPDATE disputes SET status=$1, lawyer_assigned=$2, npf_filed=$3, notes=COALESCE($4,notes) WHERE id=$5',
        [status||'active', lawyerAssigned||'', npfFiled||false, notes||null, id]);
    } catch(e1) {
      if (e1.message && e1.message.includes('notes')) {
        // Add notes column then retry
        await db.query("ALTER TABLE disputes ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT ''");
        await db.query('UPDATE disputes SET status=$1, lawyer_assigned=$2, npf_filed=$3 WHERE id=$4',
          [status||'active', lawyerAssigned||'', npfFiled||false, id]);
      } else { throw e1; }
    }
    await logActivity('Dispute updated: ' + id + ' -> ' + status);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetPayments(res) {
  try {
    const r = await db.query('SELECT * FROM payments ORDER BY created_at DESC');
    json(res, 200, { success: true, payments: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSavePayment(data, res) {
  const { ref, prop, buyer, phone, owner, ownerAcct, amount, fee, ownerAmt, status, notified, tenancy_id } = data;
  if (!ref) return json(res, 400, { error: 'Payment ref required' });
  try {
    await db.query(
      `INSERT INTO payments (ref,prop,buyer,phone,owner,owner_acct,amount,fee,owner_amt,status,notified,tenancy_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (ref) DO UPDATE SET status=$10, notified=$11, confirmed_at=CASE WHEN $10='confirmed' THEN NOW()::text ELSE payments.confirmed_at END`,
      [ref, prop||'', buyer||'', phone||'', owner||'', ownerAcct||'', amount||0, fee||0, ownerAmt||0, status||'pending', notified||'', tenancy_id||null]
    );
    await logActivity('Payment ' + (status||'pending') + ': ' + ref);
    broadcast('payment_updated', { ref, status });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetSync(res) {
  try {
    const [props, regs] = await Promise.all([
      db.query("SELECT id,title,owner,type,COALESCE(listing_type,type,'rent') as listing_type,status,price,state,lga,address,img FROM properties WHERE status='live' ORDER BY created_at DESC"),
      db.query("SELECT id,email FROM registrations WHERE status='approved'")
    ]);
    json(res, 200, {
      success: true,
      liveProperties: props.rows,
      approvedUserCount: regs.rows.length,
      lastSync: new Date().toISOString()
    });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSaveTransaction(data, res) {
  const { id, property, buyer, owner, amount, fee, status } = data;
  if (!id) return json(res, 400, { error: 'Transaction ID required' });
  try {
    await db.query(
      `INSERT INTO transactions (id,property,buyer,owner,amount,fee,status)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (id) DO UPDATE SET status=$7, owner=$3`,
      [id, property||'', buyer||'', owner||'', amount||'0', fee||'0', status||'escrow']
    );
    await logActivity('Transaction ' + id + ': ' + (status||'escrow'));
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ══════════════════════════════════════════════════════════════
// PHASE 2 — OWNER LAYER
// ══════════════════════════════════════════════════════════════

async function handleOwnerLogin(data, res) {
  const { email, code } = data;
  if (!email) return json(res, 400, { error: 'Email required' });
  const key = 'owner:' + email.toLowerCase();

  // If just requesting OTP
  if (!code) {
    const otpCode = generateOTP();
    try {
      await otpSet(key, otpCode, 10 * 60 * 1000);
      await sendEmail(email, 'GeoEstate Owner Login — Code: ' + otpCode, otpEmail(otpCode, '', 'owner-login'));
      return json(res, 200, { success: true, message: 'Code sent' });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // Verify OTP
  let record;
  try { record = await otpGet(key); } catch(e) { return json(res, 500, { error: e.message }); }
  if (!record) return json(res, 400, { error: 'No code found. Request a new one.' });
  if (Date.now() > record.expires) { await otpDelete(key); return json(res, 400, { error: 'Code expired.' }); }
  if (code !== record.code) { await otpIncrementAttempts(key); return json(res, 400, { error: 'Incorrect code.' }); }
  await otpDelete(key);

  // Find user — accept any registered email, owner role not strictly required
  try {
    const r = await db.query('SELECT * FROM registrations WHERE email=$1', [email.toLowerCase()]);
    if (!r.rows.length) return json(res, 404, {
      error: 'No account found for this email. Please register on the website first.',
      hint: 'Visit geoestate.com.ng and complete the registration form before logging in here.'
    });
    const u = r.rows[0];
    // Auto-upgrade role to owner if they're logging into owner portal
    if (u.role !== 'owner') {
      await db.query("UPDATE registrations SET role='owner', type='owner', updated_at=NOW() WHERE id=$1", [u.id]);
      u.role = 'owner';
    }
    const token = 'owner:' + u.id + ':' + Date.now();
    json(res, 200, {
      success: true,
      token,
      owner: {
        id: u.id, fname: u.fname, lname: u.lname, email: u.email,
        phone: u.phone, is_verified: u.is_verified || false, owner_since: u.owner_since,
        status: u.status, role: u.role
      }
    });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerProfile(ownerId, res) {
  try {
    const r = await db.query('SELECT id,fname,lname,email,phone,is_verified,owner_since,status,role FROM registrations WHERE id=$1', [ownerId]);
    if (!r.rows.length) return json(res, 404, { error: 'Owner not found' });
    const propCount = await db.query('SELECT COUNT(*) FROM properties WHERE owner_id=$1', [ownerId]);
    json(res, 200, { success: true, profile: { ...r.rows[0], propertyCount: parseInt(propCount.rows[0].count) } });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerVerifyIdentity(ownerId, data, res) {
  try {
    // Check if already verified
    const r = await db.query('SELECT is_verified FROM registrations WHERE id=$1', [ownerId]);
    if (r.rows[0]?.is_verified) return json(res, 200, { success: true, alreadyVerified: true, message: 'Already verified — no action needed.' });

    const { nin, doc_type, doc_url, selfie_url, dob, gender, occupation, employer, state, lga, address, next_of_kin, next_of_kin_rel, next_of_kin_phone } = data;
    // Try full update with all fields, fall back to minimal if columns missing
    try {
      await db.query(
        `UPDATE registrations SET
          nin=$1, doc=$2, is_verified=false, status=$3,
          dob=COALESCE(NULLIF($5,''),dob),
          gender=COALESCE(NULLIF($6,''),gender),
          occupation=COALESCE(NULLIF($7,''),occupation),
          employer=COALESCE(NULLIF($8,''),employer),
          state=COALESCE(NULLIF($9,''),state),
          lga=COALESCE(NULLIF($10,''),lga),
          address=COALESCE(NULLIF($11,''),address),
          next_of_kin=COALESCE(NULLIF($12,''),next_of_kin),
          next_of_kin_rel=COALESCE(NULLIF($13,''),next_of_kin_rel),
          next_of_kin_phone=COALESCE(NULLIF($14,''),next_of_kin_phone),
          updated_at=NOW()
        WHERE id=$4`,
        [nin||'', doc_type + '|' + (doc_url||''), 'review', ownerId,
         dob||'', gender||'', occupation||'', employer||'',
         state||'', lga||'', address||'',
         next_of_kin||'', next_of_kin_rel||'', next_of_kin_phone||'']
      );
    } catch(e) {
      // Fallback: minimal update if extended columns don't exist
      await db.query(
        'UPDATE registrations SET nin=$1, doc=$2, is_verified=false, status=$3, updated_at=NOW() WHERE id=$4',
        [nin||'', doc_type + '|' + (doc_url||''), 'review', ownerId]
      );
    }
    await logActivity('Owner identity submitted for review: ' + ownerId);
    json(res, 200, { success: true, message: 'Identity submitted. You will be notified once verified (usually within 24 hours).' });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerProperties(ownerId, urlFull, res) {
  try {
    const params = new URL('http://x' + urlFull).searchParams;
    const type = params.get('type');
    let q = "SELECT id,title,owner,owner_id,type,COALESCE(listing_type,type,'rent') as listing_type,status,price,COALESCE(monthly_rent,NULL) as monthly_rent,COALESCE(sale_price,NULL) as sale_price,COALESCE(lease_price,NULL) as lease_price,state,lga,address,img,COALESCE(images,'[]'::jsonb) as images,COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,COALESCE(description,'') as description,COALESCE(amenities,'[]'::jsonb) as amenities,notes,created_at FROM properties WHERE owner_id=$1";
    const args = [ownerId];
    if (type) { args.push(type); q += " AND COALESCE(listing_type,type,'rent')=$" + args.length; }
    q += ' ORDER BY created_at DESC';
    let result;
    try {
      result = await db.query(q, args);
    } catch(e1) {
      // Fallback without listing_type
      let q2 = 'SELECT id,title,owner,type,type as listing_type,status,price,state,lga,address,img,created_at FROM properties WHERE owner_id=$1';
      const a2 = [ownerId];
      if (type) { a2.push(type); q2 += ' AND type=$' + a2.length; }
      result = await db.query(q2, a2);
    }
    // Add unit counts
    // Add unit counts from DB
    let rows = result.rows;
    try {
      const ucRes = await db.query(
        "SELECT property_id, COUNT(*) as unit_count, COUNT(*) FILTER (WHERE status='vacant') as vacant_units FROM property_units WHERE property_id = ANY($1) GROUP BY property_id",
        [rows.map(r => r.id)]
      );
      const ucMap = {};
      ucRes.rows.forEach(r => { ucMap[r.property_id] = { unit_count: parseInt(r.unit_count)||0, vacant_units: parseInt(r.vacant_units)||0 }; });
      rows = rows.map(p => ({ ...p, unit_count: (ucMap[p.id]||{}).unit_count||0, vacant_units: (ucMap[p.id]||{}).vacant_units||0 }));
    } catch(ue) {
      rows = rows.map(p => ({ ...p, unit_count: 0, vacant_units: 0 }));
    }
    json(res, 200, { success: true, properties: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}


async function handleOwnerAddProperty(ownerId, data, res) {
  // Check verification
  let vrRow;
  try {
    const vr = await db.query('SELECT is_verified, status FROM registrations WHERE id=$1', [ownerId]);
    if (!vr.rows.length) return json(res, 404, { error: 'Owner not found' });
    vrRow = vr.rows[0];
  } catch(e) {
    // Fallback if is_verified column missing — check status only
    const vr2 = await db.query('SELECT status FROM registrations WHERE id=$1', [ownerId]);
    if (!vr2.rows.length) return json(res, 404, { error: 'Owner not found' });
    vrRow = { is_verified: vr2.rows[0].status === 'approved', status: vr2.rows[0].status };
  }
  // Allow listing if verified OR if admin has approved the account
  if (!vrRow.is_verified && vrRow.status !== 'approved') return json(res, 403, {
    error: 'Identity not yet verified',
    needsVerification: true,
    message: 'Please complete identity verification to list properties. You only need to do this once.'
  });

  const { title, listing_type, price, monthly_rent, sale_price, lease_price, state, lga, address, img, images, bedrooms, bathrooms, size_sqm, description, amenities, notes } = data;
  if (!title) return json(res, 400, { error: 'Property title required' });
  if (!listing_type || !['rent','buy','lease'].includes(listing_type)) return json(res, 400, { error: 'listing_type must be rent, buy, or lease' });

  const propId = 'PROP-' + Date.now();
  try {
    await db.query(
      `INSERT INTO properties (id,title,owner_id,owner,listing_type,type,status,price,monthly_rent,sale_price,lease_price,state,lga,address,img,images,bedrooms,bathrooms,size_sqm,description,amenities,notes,submitted)
       VALUES ($1,$2,$3,(SELECT fname||' '||lname FROM registrations WHERE id=$3),$4,$4,'pending',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
      [propId, title, ownerId, listing_type, price||'', monthly_rent||null, sale_price||null, lease_price||null, state||'', lga||'', address||'', img||'', JSON.stringify(images||[]), bedrooms||null, bathrooms||null, size_sqm||null, description||'', JSON.stringify(amenities||[]), notes||'', new Date().toLocaleString('en-NG')]
    );
    await logActivity('Owner ' + ownerId + ' listed new property: ' + title);
    json(res, 200, { success: true, propertyId: propId, message: 'Property submitted for review. It will go live once approved.' });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerUpdateProperty(ownerId, propId, data, res) {
  // Verify ownership
  const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
  if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  try {
    const allowed = ['title','listing_type','price','monthly_rent','sale_price','lease_price','state','lga','address','img','images','bedrooms','bathrooms','size_sqm','description','amenities','notes'];
    const fields = Object.entries(data).filter(([k]) => allowed.includes(k));
    if (!fields.length) return json(res, 400, { error: 'No valid fields' });
    const sets = fields.map(([k],i) => `${k}=$${i+2}`).join(',');
    await db.query(`UPDATE properties SET ${sets},updated_at=NOW() WHERE id=$1`, [propId, ...fields.map(([,v])=>v)]);
    await logActivity('Owner updated property: ' + propId);
    broadcast('property_updated', { id: propId });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerDeleteProperty(ownerId, propId, res) {
  const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
  if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  try {
    await db.query("UPDATE properties SET status='inactive', updated_at=NOW() WHERE id=$1", [propId]);
    broadcast('property_updated', { id: propId, status: 'inactive' });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerEnquiries(ownerId, res) {
  try {
    const r = await db.query(`
      SELECT e.*, p.title as property_title FROM enquiries e
      JOIN properties p ON p.id=e.property_id
      WHERE p.owner_id=$1 ORDER BY e.created_at DESC
    `, [ownerId]);
    json(res, 200, { success: true, enquiries: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ══════════════════════════════════════════════════════════════
// PHASE 3 — UNIT / ROOM MANAGEMENT
// ══════════════════════════════════════════════════════════════

async function handleGetUnits(ownerId, propId, res) {
  // Verify ownership if ownerId provided
  if (ownerId) {
    const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
    if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  }
  try {
    // Auto-create table if missing
    await db.query(`CREATE TABLE IF NOT EXISTS property_units (
      id SERIAL PRIMARY KEY, property_id TEXT REFERENCES properties(id) ON DELETE CASCADE,
      unit_label VARCHAR(100) NOT NULL, unit_type VARCHAR(50) DEFAULT 'room',
      floor_level VARCHAR(20) DEFAULT '', capacity INTEGER DEFAULT 1,
      monthly_price NUMERIC, status VARCHAR(20) DEFAULT 'vacant',
      current_tenant_id TEXT, occupied_since DATE, lease_end DATE,
      notes TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(()=>{});
    const r = await db.query('SELECT * FROM property_units WHERE property_id=$1 ORDER BY unit_label', [propId]);
    const stats = { total: r.rows.length, vacant: 0, occupied: 0, reserved: 0, maintenance: 0 };
    r.rows.forEach(u => { if (stats[u.status] !== undefined) stats[u.status]++; });
    json(res, 200, { success: true, units: r.rows, stats });
  } catch(e) {
    // Table might not exist yet — return empty gracefully
    if (e.message && e.message.includes('does not exist')) {
      json(res, 200, { success: true, units: [], stats: { total:0,vacant:0,occupied:0,reserved:0,maintenance:0 }, note: 'Run schema.sql to enable unit management' });
    } else { json(res, 500, { error: e.message }); }
  }
}

async function handleAddUnit(ownerId, propId, data, res) {
  if (ownerId) {
    const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
    if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  }
  const { unit_label, unit_type, floor_level, capacity, monthly_price, notes } = data;
  if (!unit_label) return json(res, 400, { error: 'unit_label required' });
  try {
    const r = await db.query(
      'INSERT INTO property_units (property_id,unit_label,unit_type,floor_level,capacity,monthly_price,notes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [propId, unit_label, unit_type||'room', floor_level||'', capacity||1, monthly_price||null, notes||'']
    );
    await logActivity('Unit added: ' + unit_label + ' to property ' + propId);
    json(res, 200, { success: true, unit: r.rows[0] });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleUpdateUnit(ownerId, propId, unitId, data, res) {
  if (ownerId) {
    const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
    if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  }
  try {
    const allowed = ['unit_label','unit_type','floor_level','capacity','monthly_price','status','current_tenant_id','occupied_since','lease_end','notes'];
    const fields = Object.entries(data).filter(([k]) => allowed.includes(k));
    if (!fields.length) return json(res, 400, { error: 'No valid fields' });
    const sets = fields.map(([k],i) => `${k}=$${i+2}`).join(',');
    const r = await db.query(`UPDATE property_units SET ${sets},updated_at=NOW() WHERE id=$1 AND property_id=$${fields.length+2} RETURNING *`,
      [unitId, ...fields.map(([,v])=>v), propId]);
    if (!r.rows.length) return json(res, 404, { error: 'Unit not found' });
    await logActivity('Unit updated: ' + unitId);
    broadcast('unit_updated', { property_id: propId, unit_id: unitId });
    json(res, 200, { success: true, unit: r.rows[0] });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteUnit(ownerId, propId, unitId, res) {
  if (ownerId) {
    const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
    if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  }
  try {
    await db.query('DELETE FROM property_units WHERE id=$1 AND property_id=$2', [unitId, propId]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Admin unit management
async function handleAdminGetUnits(propId, res) {
  try {
    // Auto-create table if missing
    await db.query(`CREATE TABLE IF NOT EXISTS property_units (
      id SERIAL PRIMARY KEY, property_id TEXT REFERENCES properties(id) ON DELETE CASCADE,
      unit_label VARCHAR(100) NOT NULL, unit_type VARCHAR(50) DEFAULT 'room',
      floor_level VARCHAR(20) DEFAULT '', capacity INTEGER DEFAULT 1,
      monthly_price NUMERIC, status VARCHAR(20) DEFAULT 'vacant',
      current_tenant_id TEXT, occupied_since DATE, lease_end DATE,
      notes TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(()=>{});
    const r = await db.query('SELECT * FROM property_units WHERE property_id=$1 ORDER BY unit_label', [propId]);
    json(res, 200, { success: true, units: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ══════════════════════════════════════════════════════════════
// PHASE 4 — ENQUIRY, SEARCH, SSE
// ══════════════════════════════════════════════════════════════

async function handleEnquiry(data, res) {
  const { property_id, property_title, name, email, phone, message, unit_id } = data;
  if (!property_id || !name || !email) return json(res, 400, { error: 'property_id, name and email required' });
  const id = 'ENQ-' + Date.now();
  try {
    // Create enquiries table if not exists (idempotent)
    await db.query(`CREATE TABLE IF NOT EXISTS enquiries (
      id TEXT PRIMARY KEY, property_id TEXT, unit_id INTEGER,
      name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT DEFAULT '',
      message TEXT DEFAULT '', status TEXT DEFAULT 'new',
      notes TEXT DEFAULT '', assigned_to TEXT DEFAULT '',
      property_title TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`).catch(()=>{});
    // Ensure all columns exist on older tables
    await db.query("ALTER TABLE enquiries ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT ''").catch(()=>{});
    await db.query("ALTER TABLE enquiries ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT ''").catch(()=>{});
    await db.query("ALTER TABLE enquiries ADD COLUMN IF NOT EXISTS property_title TEXT DEFAULT ''").catch(()=>{});
    // Resolve property title: use submitted title, or look up from DB
    let resolvedTitle = property_title || '';
    if (!resolvedTitle) {
      const tR = await db.query('SELECT title FROM properties WHERE id=$1', [property_id]).catch(()=>({ rows: [] }));
      resolvedTitle = tR.rows[0]?.title || '';
    }
    await db.query(
      'INSERT INTO enquiries (id,property_id,unit_id,name,email,phone,message,property_title) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, property_id, unit_id||null, name, email, phone||'', message||'', resolvedTitle]
    );
    // Notify owner
    const propR = await db.query('SELECT title, owner_id, (SELECT email FROM registrations WHERE id=properties.owner_id) as owner_email FROM properties WHERE id=$1', [property_id]);
    const propTitle = propR.rows[0]?.title || resolvedTitle || property_title || 'Property';
    if (propR.rows[0]?.owner_email) {
      sendEmail(propR.rows[0].owner_email, '📬 New Enquiry: ' + propTitle, enquiryEmail({name,email,phone,message}, propTitle))
        .catch(e => console.warn('Enquiry email failed:', e.message));
    }
    // Notify all sales team members instantly
    for (const sm of SALES_TEAM) {
      sendEmail(
        sm.email,
        '🔔 New Lead: ' + name + ' — ' + propTitle,
        salesAlertEmail({name, email, phone: phone||'—', message: message||''}, propTitle, sm)
      ).catch(e => console.warn('Sales alert email failed for ' + sm.email + ':', e.message));
    }
    await logActivity('Enquiry received for property ' + property_id + ' from ' + name);
    broadcast('new_enquiry', { property_id, name });
    // Return sales contact info to frontend
    json(res, 200, {
      success: true,
      enquiryId: id,
      salesTeam: SALES_TEAM.map(s => ({ name: s.name, title: s.title, phone: s.phone, whatsapp: s.whatsapp, email: s.email }))
    });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetAdminEnquiries(res) {
  try {
    const r = await db.query(`
      SELECT e.id, e.property_id, e.unit_id, e.name, e.email, e.phone,
             e.message, e.status, e.notes, e.assigned_to, e.created_at,
             COALESCE(NULLIF(e.property_title,''), p.title, e.property_id) as property_title
      FROM enquiries e
      LEFT JOIN properties p ON p.id=e.property_id
      ORDER BY e.created_at DESC
    `);
    json(res, 200, { success: true, enquiries: r.rows });
  } catch(e) {
    // Enquiries table may not exist yet — return empty gracefully
    if (e.message && (e.message.includes('does not exist') || e.message.includes('relation'))) {
      json(res, 200, { success: true, enquiries: [], note: 'Run schema.sql to enable enquiries' });
    } else { json(res, 500, { error: e.message }); }
  }
}

// ── SSE endpoint ──
function handleSSE(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  res.write('data: {"type":"connected"}\n\n');
  sseClients.add(res);
  // Keep-alive ping every 30s
  const ping = setInterval(() => {
    try { res.write(':ping\n\n'); } catch(e) { clearInterval(ping); sseClients.delete(res); }
  }, 30000);
  req.on('close', () => { clearInterval(ping); sseClients.delete(res); });
}

// ── HTTP Server ───────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  const url     = req.url.split('?')[0];
  const urlFull = req.url;

  // ── GET routes ──
  if (req.method === 'GET') {
    if (url === '/')
      return db.query('SELECT COUNT(*) FROM registrations').then(r => json(res,200,{status:'ok',service:'GeoEstate API',version:'2.0',db:'neon',registrations:r.rows[0].count})).catch(()=>json(res,200,{status:'ok',service:'GeoEstate API',version:'2.0'}));
    if (url === '/health') return json(res, 200, { status: 'ok', service: 'GeoEstate API', version: '2.0' });


    // Public — no auth required
    if (url === '/properties')               return handlePublicProperties(urlFull, res);
    if (url.match(/^\/properties\/([^/]+)$/)) return handlePublicPropertyById(url.split('/')[2], res);
    if (url === '/events')                   return handleSSE(req, res);

    // Admin routes — require token
    if (url.startsWith('/admin/')) {
      if (!requireAdmin(req, res)) return;
      if (url === '/admin/me') {
        const payload = requireAdmin(req, res);
        if (!payload) return;
        return json(res, 200, { success: true, email: payload.email, role: payload.role });
      }
      if (url === '/admin/registrations')    return handleGetRegistrations(urlFull, res);
      if (url === '/admin/properties')       return handleGetProperties(res);
      if (url === '/admin/team')             return handleGetTeam(res);
      if (url === '/admin/lawyers')          return handleGetLawyers(res);
      if (url === '/admin/transactions')     return handleGetTransactions(res);
      if (url === '/admin/tenancies')        return handleGetTenancies(res);
      if (url === '/admin/activity')         return handleGetActivityLog(res);
      if (url === '/admin/disputes')         return handleGetDisputes(res);
      if (url === '/admin/payments')         return handleGetPayments(res);
      if (url === '/admin/sync')             return handleGetSync(res);
      if (url === '/admin/enquiries')        return handleGetAdminEnquiries(res);
      const unitAdminMatch = url.match(/^\/admin\/property\/([^/]+)\/units$/);
      if (unitAdminMatch)                    return handleAdminGetUnits(unitAdminMatch[1], res);
      return json(res, 404, { error: 'Not found' });
    }

    // Owner routes
    if (url.startsWith('/owner/')) {
      const ownerId = requireOwner(req, res);
      if (!ownerId) return;
      if (url === '/owner/profile')          return handleOwnerProfile(ownerId, res);
      if (url === '/owner/properties')       return handleOwnerProperties(ownerId, urlFull, res);
      if (url === '/owner/enquiries')        return handleOwnerEnquiries(ownerId, res);
      const propDetailMatch = url.match(/^\/owner\/property\/([^/]+)\/detail$/);
      if (propDetailMatch) return handleOwnerPropertyDetail(ownerId, propDetailMatch[1], res);
      const unitMatch = url.match(/^\/owner\/property\/([^/]+)\/units$/);
      if (unitMatch)                         return handleGetUnits(ownerId, unitMatch[1], res);
      return json(res, 404, { error: 'Not found' });
    }

    return json(res, 404, { error: 'Not found' });
  }

  // ── DELETE routes ──
  if (req.method === 'DELETE') {
    if (url.startsWith('/admin/')) {
      if (!requireAdmin(req, res)) return;
      const tmMatch = url.match(/^\/admin\/team\/(\d+)$/);
      if (tmMatch) return handleDeleteTeamMember(tmMatch[1], res);
      const lwMatch = url.match(/^\/admin\/lawyer\/(\d+)$/);
      if (lwMatch) return handleDeleteLawyer(lwMatch[1], res);
      const prMatch = url.match(/^\/admin\/property\/([^/]+)$/);
      if (prMatch) return handleDeleteProperty(prMatch[1], res);
      const tnMatch = url.match(/^\/admin\/tenancy\/(\d+)$/);
      if (tnMatch) return handleDeleteTenancy(tnMatch[1], res);
    }
    if (url.startsWith('/owner/')) {
      const ownerId = requireOwner(req, res);
      if (!ownerId) return;
      const owPropMatch = url.match(/^\/owner\/property\/([^/]+)$/);
      if (owPropMatch) return handleOwnerDeleteProperty(ownerId, owPropMatch[1], res);
      const owUnitMatch = url.match(/^\/owner\/property\/([^/]+)\/units\/(\d+)$/);
      if (owUnitMatch) return handleDeleteUnit(ownerId, owUnitMatch[1], owUnitMatch[2], res);
    }
    return json(res, 404, { error: 'Not found' });
  }

  // ── POST / PATCH routes ──
  if (req.method === 'POST' || req.method === 'PATCH') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const data = body ? JSON.parse(body) : {};

        // Public endpoints
        if (url === '/admin/login')            return handleAdminLogin(data, res);
        if (url === '/admin/logout')           return handleAdminLogout(req, res);
        if (url === '/send-otp')             return handleSendOTP(data, res);
        if (url === '/verify-otp')           return handleVerifyOTP(data, res);
        if (url === '/register')             return handleRegister(data, res);
        if (url === '/user/login')            return handleUserLogin(data, res);
        if (url === '/enquiry')              return handleEnquiry(data, res);
        if (url === '/upload-sign')           return handleSupabaseUploadSign(data, res);
        if (url === '/submit-dispute')       return handleSubmitDispute(data, res);

        // Owner auth (no token needed)
        if (url === '/owner/login')          return handleOwnerLogin(data, res);

        // Owner routes (token required)
        if (url.startsWith('/owner/')) {
          const ownerId = requireOwner(req, res);
          if (!ownerId) return;
          if (url === '/owner/verify-identity') return handleOwnerVerifyIdentity(ownerId, data, res);
          if (url === '/owner/add-property')    return handleOwnerAddProperty(ownerId, data, res);
          const owPropMatch = url.match(/^\/owner\/property\/([^/]+)$/);
          if (owPropMatch) return handleOwnerUpdateProperty(ownerId, owPropMatch[1], data, res);
          const owUnitMatch = url.match(/^\/owner\/property\/([^/]+)\/units$/);
          if (owUnitMatch) return handleAddUnit(ownerId, owUnitMatch[1], data, res);
          const owUnitPatch = url.match(/^\/owner\/property\/([^/]+)\/units\/(\d+)$/);
          if (owUnitPatch) return handleUpdateUnit(ownerId, owUnitPatch[1], owUnitPatch[2], data, res);
          return json(res, 404, { error: 'Not found' });
        }

        // Admin routes (token required)
        if (url.startsWith('/admin/') || url === '/submit-property') {
          if (url !== '/submit-property' && !requireAdmin(req, res)) return;
          if (url === '/submit-property')           return handleSaveProperty(data, res);
          if (url === '/admin/save-property')       return handleSaveProperty(data, res);
          if (url === '/admin/create-property')     return handleSaveProperty(data, res);
          if (url === '/admin/save-lawyer')         return handleSaveLawyer(data, res);
          if (url === '/admin/save-team')           return handleSaveTeamMember(data, res);
          if (url === '/admin/save-tenancy')        return handleSaveTenancy(data, res);
          if (url === '/admin/save-payment')        return handleSavePayment(data, res);
          if (url === '/admin/save-transaction')    return handleSaveTransaction(data, res);
          const disUpdate = url.match(/^\/admin\/dispute\/([^/]+)$/);
          if (disUpdate) return handleUpdateDispute(disUpdate[1], data, res);
          const unitAdminAdd = url.match(/^\/admin\/property\/([^/]+)\/units$/);
          if (unitAdminAdd) return handleAddUnit(null, unitAdminAdd[1], data, res);
          const unitAdminPatch = url.match(/^\/admin\/property\/([^/]+)\/units\/(\d+)$/);
          if (unitAdminPatch) return handleUpdateUnit(null, unitAdminPatch[1], unitAdminPatch[2], data, res);
          if (url.startsWith('/admin/registration/') || url.startsWith('/admin/property/') || url.startsWith('/admin/tenancy/') || url.startsWith('/admin/enquiry/'))
            return handleAdminUpdate(url, data, res);
          return json(res, 404, { error: 'Not found' });
        }

        return json(res, 404, { error: 'Not found' });
      } catch(e) { json(res, 400, { error: 'Bad request: ' + e.message }); }
    });
    return;
  }

  json(res, 405, { error: 'Method not allowed' });
});



// ── Owner: Get full property detail ──────────────────────────────────────────
async function handleOwnerPropertyDetail(ownerId, propId, res) {
  try {
    const r = await db.query(
      `SELECT id,title,owner,owner_id,type,COALESCE(listing_type,type,'rent') as listing_type,status,price,
       COALESCE(monthly_rent,NULL) as monthly_rent,COALESCE(sale_price,NULL) as sale_price,COALESCE(lease_price,NULL) as lease_price,
       state,lga,address,img,COALESCE(images,'[]'::jsonb) as images,
       COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,
       COALESCE(description,'') as description,COALESCE(amenities,'[]'::jsonb) as amenities,notes,created_at
       FROM properties WHERE id=$1 AND owner_id=$2`,
      [propId, ownerId]
    );
    if (!r.rows.length) return json(res, 404, { error: 'Property not found' });
    const prop = r.rows[0];
    try {
      const ur = await db.query("SELECT id,unit_label,unit_type,floor_level,capacity,monthly_price,status FROM property_units WHERE property_id=$1 ORDER BY unit_label", [propId]);
      prop.units = ur.rows;
    } catch(e) { prop.units = []; }
    json(res, 200, { success: true, property: prop });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── Cloudinary: Generate signed upload parameters ──────────────────────────
// ── Supabase Storage upload — POST /upload-sign ─────────────────────────────
// Strategy: server creates a signed upload URL for the browser to PUT directly
// to Supabase Storage. File bytes never touch this server.
// Supabase Storage bucket: "geoestate-docs" (create this in Supabase Dashboard)
async function handleSupabaseUploadSign(data, res) {
  const SUPABASE_URL         = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
  const BUCKET               = process.env.SUPABASE_BUCKET || 'geoestate-docs';

  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    return json(res, 503, { error: 'Storage not configured. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in Railway environment variables.' });
  }

  const folder    = (data.folder || 'uploads').replace(/[^a-zA-Z0-9/_-]/g, '');
  const ext       = data.ext || 'bin';
  const filename  = folder + '/' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.' + ext;

  try {
    // Create a signed upload URL via Supabase Storage REST API
    const signRes = await fetch(
      `${SUPABASE_URL}/storage/v1/object/upload/sign/${BUCKET}/${filename}`,
      {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + SUPABASE_SERVICE_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ upsert: false })
      }
    );
    if (!signRes.ok) {
      const err = await signRes.text();
      return json(res, 500, { error: 'Could not create signed URL: ' + err });
    }
    const signData = await signRes.json();
    // signedURL is the path for the browser to PUT to
    // Public URL is how we read the file back
    const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/${BUCKET}/${filename}`;
    json(res, 200, {
      signed_url:  SUPABASE_URL + '/storage/v1' + signData.url,
      public_url:  publicUrl,
      token:       signData.token,
      path:        filename,
      bucket:      BUCKET
    });
  } catch(e) {
    json(res, 500, { error: e.message });
  }
}


// ── Admin Login — POST /admin/login ──────────────────────────────────────────
// Validates ADMIN_EMAIL + ADMIN_PASSWORD env vars, returns a signed JWT.
// The raw password/secret NEVER leaves the server.
async function handleAdminLogin(data, res) {
  const { email, password } = data;
  if (!email || !password) return json(res, 400, { error: 'Email and password required' });

  // Constant-time comparison — pad buffers to same length to prevent
  // timingSafeEqual throwing on length mismatch (which causes a 524 timeout)
  function safeEqual(a, b) {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    // Always compare max-length buffer to avoid short-circuit timing leak
    const maxLen = Math.max(ba.length, bb.length);
    const pa = Buffer.concat([ba, Buffer.alloc(maxLen - ba.length)]);
    const pb = Buffer.concat([bb, Buffer.alloc(maxLen - bb.length)]);
    return crypto.timingSafeEqual(pa, pb) && ba.length === bb.length;
  }
  const emailOk    = safeEqual(email.toLowerCase().trim(), ADMIN_EMAIL.toLowerCase().trim());
  const passwordOk = safeEqual(password, ADMIN_PASSWORD);

  if (!emailOk || !passwordOk) {
    await new Promise(r => setTimeout(r, 500)); // slow down brute force
    return json(res, 401, { error: 'Invalid email or password' });
  }

  const token = jwtSign({ role: 'admin', email: ADMIN_EMAIL }, JWT_SECRET, 8);
  await logActivity('Admin login: ' + ADMIN_EMAIL).catch(() => {});
  json(res, 200, { success: true, token, expiresIn: '8h' });
}

// ── Admin Logout — POST /admin/logout ────────────────────────────────────────
// Stateless JWT — logout is handled client-side by deleting the token.
// This endpoint exists for audit logging purposes.
async function handleAdminLogout(req, res) {
  await logActivity('Admin logout').catch(() => {});
  json(res, 200, { success: true });
}


const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log('✅ GeoEstate API v2.0 running on port ' + PORT));
