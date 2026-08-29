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
// Firebase Cloud Messaging (push notifications). Not configured yet -- needs
// a Firebase project's service account JSON pasted into this env var (as a
// single-line JSON string, or base64-encoded). Every push call below no-ops
// silently until this is set, same graceful-degradation pattern as the rest
// of this file (e.g. RESEND_API_KEY for email).
const FCM_SERVICE_ACCOUNT_RAW = process.env.SECRET_FCM_SERVICE_ACCOUNT || '';
// ── Admin Auth Config ────────────────────────────────────────────────────────
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL;

// Fixed, well-known ID for the shared "GeoEstate Support" account —
// customers chat with this single identity rather than with a property's
// actual owner directly (GeoEstate manages the transaction, not the
// owner), and any staff member with access to its email can log in via
// the existing owner OTP flow and see every customer conversation in one
// shared Messages inbox. See ensureSupportAccount() below, which creates
// this account automatically on boot if it doesn't already exist.
const SUPPORT_USER_ID = 'SUPPORT-001';
const SUPPORT_EMAIL = 'geoestate.ng@gmail.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET     = process.env.JWT_SECRET;
if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !JWT_SECRET) {
  console.error('FATAL: ADMIN_EMAIL, ADMIN_PASSWORD, and JWT_SECRET must all be set in Railway environment variables.');
  process.exit(1);
}

// ── Partner Portal directory ─────────────────────────────────────────────────
// Set PARTNERS_JSON in the environment, e.g.:
//   [{"name":"Adebayo Taofeek","token":"..."},{"name":"Olawale Ayuba","token":"..."}]
// Each partner gets a stable pseudo-owner-id (PARTNER-<slug>) so their listings
// stay isolated from real property owners and from each other, reusing the
// existing owner:<id>:<timestamp> token scheme and /owner/* endpoints.
let PARTNERS = [];
try { PARTNERS = JSON.parse(process.env.PARTNERS_JSON || '[]'); } catch(e) {
  console.warn('PARTNERS_JSON is not valid JSON — partner login will reject everyone until fixed.');
}
function partnerSlug(name) {
  return 'PARTNER-' + String(name).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
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
  // Token format: owner:<userId>:<timestamp>, with an optional trailing
  // "s<staffId>" segment for support-staff logins (see getStaffIdFromToken)
  // identifying which individual staff member is behind the shared
  // SUPPORT_USER_ID identity. Stripped here first so timestamp/userId
  // parsing below is completely unaffected either way, and every existing
  // caller of requireOwner keeps getting back exactly the same plain
  // userId string it always has.
  const parts = token.split(':');
  if (parts.length < 3) { json(res, 401, { error: 'Invalid token format' }); return null; }
  if (/^s\d+$/.test(parts[parts.length - 1])) parts.pop();
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
  // Fire-and-forget (requireOwner is called synchronously everywhere, so
  // this can't be awaited without touching every call site) — powers the
  // "delivered" chat status: a message counts as delivered once the
  // recipient has been active anywhere in the app since it was sent, not
  // just when they open that specific thread (that's what read_at means).
  db.query('UPDATE registrations SET last_active_at=NOW() WHERE id=$1', [userId]).catch(() => {});
  return userId;
}

// Support staff share one login identity (SUPPORT_USER_ID) everywhere else
// in the backend for simplicity, but chat attribution, claims, and presence
// need to know which individual staff member is actually behind a given
// request. Re-parses the same token independently rather than changing
// requireOwner's return type, so nothing that already calls requireOwner
// needs to change.
function getStaffIdFromToken(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const parts = token.split(':');
  const m = /^s(\d+)$/.exec(parts[parts.length - 1]);
  return m ? parseInt(m[1]) : null;
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

// ── Push notifications (Firebase Cloud Messaging, HTTP v1 API) ──────────────
function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

let _fcmAccount = null;
function getFcmAccount() {
  if (_fcmAccount) return _fcmAccount;
  if (!FCM_SERVICE_ACCOUNT_RAW) return null;
  try {
    // Accept either raw JSON or base64-encoded JSON in the env var.
    const raw = FCM_SERVICE_ACCOUNT_RAW.trim().startsWith('{')
      ? FCM_SERVICE_ACCOUNT_RAW
      : Buffer.from(FCM_SERVICE_ACCOUNT_RAW, 'base64').toString('utf8');
    _fcmAccount = JSON.parse(raw);
    return _fcmAccount;
  } catch (e) { console.error('Invalid SECRET_FCM_SERVICE_ACCOUNT:', e.message); return null; }
}

let _fcmTokenCache = { token: null, expiresAt: 0 };
async function getFcmAccessToken() {
  const account = getFcmAccount();
  if (!account) return null;
  if (_fcmTokenCache.token && Date.now() < _fcmTokenCache.expiresAt - 60000) return _fcmTokenCache.token;

  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: account.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600, iat: now
  }));
  const signInput = header + '.' + claims;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signInput);
  const signature = base64url(signer.sign(account.private_key));
  const jwt = signInput + '.' + signature;

  return new Promise((resolve) => {
    const body = 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + encodeURIComponent(jwt);
    const req = https.request({
      hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const p = JSON.parse(d);
          if (p.access_token) {
            _fcmTokenCache = { token: p.access_token, expiresAt: Date.now() + (p.expires_in || 3600) * 1000 };
            resolve(p.access_token);
          } else { console.error('FCM token error:', d); resolve(null); }
        } catch (e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null)); req.write(body); req.end();
  });
}

// Silently no-ops if FCM isn't configured yet — same graceful-degradation
// pattern as sendEmail. Never throws; callers don't need to wrap in try/catch.
async function sendPushNotification(deviceToken, title, body, data) {
  if (!deviceToken) return { skipped: true };
  const account = getFcmAccount();
  if (!account) return { skipped: true, reason: 'FCM not configured' };
  try {
    const accessToken = await getFcmAccessToken();
    if (!accessToken) return { skipped: true, reason: 'Could not get FCM access token' };
    // FCM's data field must be Map<string,string> — any non-string value
    // (e.g. a numeric tenancy_id) causes the whole request to be rejected,
    // which previously would have been completely silent since the result
    // was discarded at the call site.
    const stringData = {};
    Object.keys(data || {}).forEach(k => { stringData[k] = String(data[k]); });
    const payload = JSON.stringify({
      message: {
        token: deviceToken,
        notification: { title, body },
        data: stringData,
        android: { priority: 'high' }
      }
    });
    return await new Promise((resolve) => {
      const req = https.request({
        hostname: 'fcm.googleapis.com',
        path: '/v1/projects/' + account.project_id + '/messages:send',
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
      }, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => { resolve({ ok: res.statusCode === 200, status: res.statusCode, body: d }); });
      });
      req.on('error', (e) => resolve({ ok: false, error: e.message })); req.write(payload); req.end();
    });
  } catch (e) { return { ok: false, error: e.message }; }
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
      'SELECT id, fname, lname, email, phone, role, status, is_verified, pass_hash, photo_url FROM registrations WHERE email = $1',
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
    // Issue the same owner:<id>:<timestamp> token the /owner/* endpoints and
    // the owner-dashboard's OTP login already use. Without this, the frontend's
    // "bridge straight into an owner session on regular login" logic
    // (GeoAPI.setOwnerSession, wired up in doLogin()) has nothing to store —
    // data.token is always undefined — so every customer login silently fails
    // to skip the owner dashboard's separate OTP screen, even after a
    // successful password login.
    const token = 'owner:' + user.id + ':' + Date.now();
    json(res, 200, {
      success: true,
      token,
      user: {
        id:       user.id,
        fname:    user.fname,
        lname:    user.lname,
        email:    user.email,
        phone:    user.phone,
        role:     user.role,
        verified: user.is_verified || false,
        photo_url: user.photo_url || ''
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
    const exists = await db.query('SELECT id, is_verified FROM registrations WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length) {
      // Was returning {success:true} with NO submissionId at all. The
      // frontend's sessionUser.id = regData.submissionId || ('USR-'+Date.now())
      // fallback then generated a brand-new ID matching no real row in the
      // DB. Every action after that — most importantly identity verification
      // (selfie/ID doc upload) — silently targeted a nonexistent row: the
      // UPDATE matched zero rows (not a SQL error), so the frontend reported
      // success while nothing was ever actually saved against the person's
      // real registration. This is very likely what happened for anyone
      // whose files "definitely uploaded" but never appeared in admin. Now
      // returns the real existing ID so a repeat signup attempt (closed the
      // app mid-OTP, tried again, etc. — an easy thing to do) still lets
      // them log in and continue against their actual record.
      const ownerToken = 'owner:' + exists.rows[0].id + ':' + Date.now();
      return json(res, 200, {
        success: true, message: 'Already registered', submissionId: exists.rows[0].id,
        token: ownerToken, alreadyVerified: !!exists.rows[0].is_verified
      });
    }
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
    // Same gap as /user/login: without this token the frontend's
    // GeoAPI.setOwnerSession() call after registration has nothing to store,
    // so a brand-new account still hits the owner dashboard's separate OTP
    // screen the first time they try to list a property.
    const token = 'owner:' + subId + ':' + Date.now();
    json(res, 200, { success: true, submissionId: subId, token });
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

    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_verified BOOLEAN DEFAULT FALSE`).catch(() => {});
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_date DATE`).catch(() => {});

    let query = "SELECT id, title, owner, owner_id, type, COALESCE(listing_type, type, 'rent') as listing_type, status, price, state, lga, address, img, created_at, COALESCE(site_visit_verified,false) as site_visit_verified, (SELECT is_verified FROM registrations WHERE id=properties.owner_id) as owner_verified FROM properties WHERE status='live'";
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


// Increments a property's view counter — called once per property per
// browser session (deduped client-side via sessionStorage, not here) when
// its detail page loads. Deliberately simple: a single incrementing
// counter rather than a full events table with per-viewer rows, since
// "roughly how many people looked at this listing" is what an owner
// actually wants to see, not a detailed audit trail.
async function handleRecordPropertyView(id, res) {
  try {
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0`).catch(() => {});
    await db.query('UPDATE properties SET view_count = COALESCE(view_count,0) + 1 WHERE id=$1', [id]);
    json(res, 200, { success: true });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function handlePublicPropertyById(id, res) {
  try {
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_verified BOOLEAN DEFAULT FALSE`).catch(() => {});
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_date DATE`).catch(() => {});
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_notes TEXT DEFAULT ''`).catch(() => {});
    let prop;
    try {
      const r = await db.query(
        "SELECT id,title,owner,owner_id,type,COALESCE(listing_type,type,'rent') as listing_type,status,price,COALESCE(monthly_rent,NULL) as monthly_rent,COALESCE(annual_rent,NULL) as annual_rent,COALESCE(nightly_rate,NULL) as nightly_rate,COALESCE(sale_price,NULL) as sale_price,COALESCE(lease_price,NULL) as lease_price,state,lga,address,img,COALESCE(images,'[]'::jsonb) as images,video_url,COALESCE(docs,'[]'::jsonb) as docs,COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,COALESCE(description,'') as description,COALESCE(amenities,'[]'::jsonb) as amenities,notes,created_at,COALESCE(site_visit_verified,false) as site_visit_verified,site_visit_date,COALESCE(site_visit_notes,'') as site_visit_notes,(SELECT is_verified FROM registrations WHERE id=properties.owner_id) as owner_verified FROM properties WHERE id=$1",
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
      const ur = await db.query("SELECT id,unit_label,unit_type,floor_level,capacity,monthly_price,status,occupied_since,lease_end,COALESCE(images,'[]'::jsonb) as images,COALESCE(description,'') as description FROM property_units WHERE property_id=$1 ORDER BY unit_label", [id]);
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
    // Was `WHERE created_at > $1` only — so once a registration had been seen
    // by one poll, a LATER update (e.g. a customer finishing identity
    // verification: selfie/doc uploaded, NIN submitted) never showed up on
    // any subsequent poll, since that's an UPDATE (bumps updated_at) not a
    // new row (created_at unchanged). The data was genuinely saved in the DB;
    // the admin's local copy was just frozen at whatever it looked like the
    // first time it was ever fetched. Catch both new AND updated rows now.
    if (since) {
      q = 'SELECT * FROM registrations WHERE created_at > $1 OR updated_at > $1 ORDER BY created_at DESC';
      params.push(new Date(parseInt(since)));
    }
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
      photo_url: r.photo_url||'', id_doc_url: r.id_doc_url||'', other_doc_url: r.other_doc_url||'',
      nextOfKin: r.next_of_kin||'—', nextOfKinRel: r.next_of_kin_rel||'—',
      nextOfKinPhone: r.next_of_kin_phone||'—',
      isVerified: r.is_verified||false
    }));
    json(res, 200, { success: true, count: rows.length, registrations: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetProperties(res) {
  try {
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_verified BOOLEAN DEFAULT FALSE`).catch(() => {});
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_date DATE`).catch(() => {});
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_notes TEXT DEFAULT ''`).catch(() => {});
    // Use safe column list that works with both old and new schema
    const result = await db.query(`
      SELECT id, title, owner, owner_id, type,
        COALESCE(listing_type, type, 'rent') as listing_type,
        status, price,
        COALESCE(monthly_rent, CASE WHEN type='rent' THEN NULL ELSE NULL END) as monthly_rent,
        COALESCE(annual_rent, NULL) as annual_rent,
        COALESCE(nightly_rate, NULL) as nightly_rate,
        COALESCE(sale_price, NULL) as sale_price,
        COALESCE(lease_price, NULL) as lease_price,
        state, lga, address, img,
        COALESCE(images, '[]'::jsonb) as images,
        video_url,
        COALESCE(docs, '[]'::jsonb) as docs,
        COALESCE(metadata, '{}'::jsonb) as metadata,
        doc_coo, doc_deed, doc_survey, doc_approval, sale_agreement,
        agreement_doc,
        COALESCE(bedrooms, NULL) as bedrooms,
        COALESCE(bathrooms, NULL) as bathrooms,
        COALESCE(size_sqm, NULL) as size_sqm,
        COALESCE(description, '') as description,
        COALESCE(amenities, '[]'::jsonb) as amenities,
        notes, submitted, created_at, updated_at,
        COALESCE(site_visit_verified, false) as site_visit_verified,
        site_visit_date, COALESCE(site_visit_notes, '') as site_visit_notes
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

// Owner-scoped Tenancy Tracker — same shape as the admin version, but joined
// against properties so an owner only ever sees tenancies on properties they
// actually own (tenancies has no owner_id column of its own, only the
// free-text 'owner' name field, which isn't reliable enough to filter on —
// property_id -> properties.owner_id is the real, trustworthy link).
async function handleOwnerTenancies(ownerId, res) {
  try {
    const result = await db.query(`
      SELECT t.*,
        CASE WHEN t.end_date <= CURRENT_DATE + INTERVAL '30 days' AND t.status='active' THEN true ELSE false END as expiring_soon
      FROM tenancies t
      JOIN properties p ON p.id = t.property_id
      WHERE p.owner_id = $1
      ORDER BY t.end_date ASC
    `, [ownerId]);
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

// The customer/tenant-facing equivalent of handleOwnerTenancies above —
// same shape, scoped by tenant_id instead of the property's owner_id.
// This was the actual missing piece behind "tenancy tracker" and
// "e-signature" only ever being reachable from the Owner Dashboard: the
// backend for a tenant viewing/signing their own agreement already
// existed (getTenancyForUser already resolves role as 'owner' or
// 'tenant'), there was just no endpoint for a tenant to find their own
// tenancy id in the first place, and no customer-facing screen to call it.
async function handleMyTenancies(tenantId, res) {
  try {
    const result = await db.query(`
      SELECT t.*, p.owner_id as resolved_owner_id,
        CASE WHEN t.end_date <= CURRENT_DATE + INTERVAL '30 days' AND t.status='active' THEN true ELSE false END as expiring_soon
      FROM tenancies t
      LEFT JOIN properties p ON p.id = t.property_id
      WHERE t.tenant_id = $1
      ORDER BY t.end_date ASC
    `, [tenantId]);
    const rows = result.rows.map(r => ({
      id: r.id, ref: r.ref, type: r.type, property: r.property,
      propertyId: r.property_id, unitId: r.unit_id,
      tenant: r.tenant, owner: r.owner, ownerId: r.resolved_owner_id || '',
      amount: r.amount, start: r.start_date, end: r.end_date,
      status: r.status, packingOutDate: r.packing_out_date,
      renewedAt: r.renewed_at, vacatedAt: r.vacated_at,
      expiringSoon: r.expiring_soon
    }));
    json(res, 200, { success: true, tenancies: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── E-signature tenancy agreements ───────────────────────────────────────
// A typed-name signature + timestamp, a widely-used and generally accepted
// e-signature pattern — not a full certificate-based e-signature system.
// Legal validity of a typed signature varies by jurisdiction and use case,
// so this doesn't claim to replace professional legal counsel for
// high-stakes agreements; the generated document says as much too.
async function ensureAgreementsTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS tenancy_agreements (
    id SERIAL PRIMARY KEY, tenancy_id INTEGER NOT NULL REFERENCES tenancies(id) ON DELETE CASCADE UNIQUE,
    content TEXT NOT NULL, owner_signature TEXT, owner_signed_at TIMESTAMPTZ,
    tenant_signature TEXT, tenant_signed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
  // Self-heals an already-existing table from before owner bank details
  // were captured at signing.
  await db.query(`ALTER TABLE tenancy_agreements ADD COLUMN IF NOT EXISTS owner_bank_name TEXT`).catch(() => {});
  await db.query(`ALTER TABLE tenancy_agreements ADD COLUMN IF NOT EXISTS owner_account_number TEXT`).catch(() => {});
  await db.query(`ALTER TABLE tenancy_agreements ADD COLUMN IF NOT EXISTS owner_account_name TEXT`).catch(() => {});
}

// Determines whether the given user is the owner or the tenant on a
// tenancy (or neither, in which case they have no business seeing/signing
// it) — a tenancy can legitimately have no linked tenant_id at all (an
// auto-created tenancy where the payer's email didn't match any
// registered account), in which case only the owner can view/sign here.
async function getTenancyForUser(userId, tenancyId) {
  const r = await db.query(`
    SELECT t.*, p.owner_id as property_owner_id, p.title as property_title
    FROM tenancies t
    LEFT JOIN properties p ON p.id = t.property_id
    WHERE t.id = $1
  `, [tenancyId]);
  if (!r.rows.length) return null;
  const t = r.rows[0];
  let role = null;
  if (t.property_owner_id && t.property_owner_id === userId) role = 'owner';
  else if (t.tenant_id && t.tenant_id === userId) role = 'tenant';
  return { tenancy: t, role };
}

function generateAgreementText(t) {
  const fmt = (d) => d ? new Date(d).toLocaleDateString('en-NG', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';
  return `TENANCY AGREEMENT

LANDLORD/OWNER: ${t.owner || '—'}
TENANT: ${t.tenant || '—'}

PROPERTY: ${t.property || t.property_title || '—'}
TENANCY TYPE: ${(t.type || 'rent').toUpperCase()}
COMMENCEMENT DATE: ${fmt(t.start_date)}
EXPIRY DATE: ${fmt(t.end_date)}
AMOUNT: ₦${Number(t.amount || 0).toLocaleString()}

TERMS

1. The Tenant agrees to pay the amount stated above for the tenancy period stated above.
2. The Tenant shall maintain the property in good condition and report any damage promptly to the Owner.
3. Renewal notice will be given at least 2 months before expiry, per GeoEstate's standard renewal policy.
4. If the tenancy is not renewed by expiry, the Tenant shall vacate within 3 weeks — the standard packing-out period.
5. Any disputes shall first be addressed through GeoEstate's dispute resolution process before any other action is taken.

This agreement was generated via the GeoEstate platform and reflects the tenancy details recorded at the time of confirmation. It does not replace, and the parties are encouraged to seek, independent legal advice for their specific circumstances.

By signing below, both parties acknowledge they have read and agree to the terms above.`;
}

async function handleGetTenancyAgreement(userId, tenancyId, res) {
  try {
    await ensureAgreementsTable();
    const info = await getTenancyForUser(userId, tenancyId);
    if (!info) return json(res, 404, { error: 'Tenancy not found' });
    if (!info.role) return json(res, 403, { error: 'You are not a party to this tenancy' });
    let agR = await db.query('SELECT * FROM tenancy_agreements WHERE tenancy_id=$1', [tenancyId]);
    let agreement;
    if (!agR.rows.length) {
      const content = generateAgreementText(info.tenancy);
      const ins = await db.query('INSERT INTO tenancy_agreements (tenancy_id, content) VALUES ($1,$2) RETURNING *', [tenancyId, content]);
      agreement = ins.rows[0];
    } else {
      agreement = agR.rows[0];
    }
    json(res, 200, { success: true, agreement, role: info.role });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSignTenancyAgreement(userId, tenancyId, data, res) {
  const signature = (data.signature || '').toString().trim();
  if (!signature) return json(res, 400, { error: 'Signature (typed full name) required' });
  try {
    await ensureAgreementsTable();
    const info = await getTenancyForUser(userId, tenancyId);
    if (!info) return json(res, 404, { error: 'Tenancy not found' });
    if (!info.role) return json(res, 403, { error: 'You are not a party to this tenancy' });
    const agR = await db.query('SELECT id FROM tenancy_agreements WHERE tenancy_id=$1', [tenancyId]);
    if (!agR.rows.length) return json(res, 400, { error: 'Agreement not generated yet — view it first' });

    if (info.role === 'owner') {
      // Captured directly from the owner at the moment of signing — a
      // stronger source of truth than the free-text owner_acct field admin
      // types in manually elsewhere, usually from a phone call/WhatsApp
      // message with no verification at all. Required (not optional) so
      // admin always has a real, owner-supplied payout destination on file
      // by the time an agreement is fully signed, not just a signature.
      const bankName = (data.bank_name || '').toString().trim();
      const accountNumber = (data.account_number || '').toString().trim();
      const accountName = (data.account_name || '').toString().trim();
      if (!bankName || !accountNumber || !accountName) {
        return json(res, 400, { error: 'Bank name, account number, and account name are all required to sign as the owner' });
      }
      await db.query(
        `UPDATE tenancy_agreements SET owner_signature=$1, owner_signed_at=NOW(), owner_bank_name=$2, owner_account_number=$3, owner_account_name=$4 WHERE tenancy_id=$5`,
        [signature, bankName, accountNumber, accountName, tenancyId]
      );
    } else {
      await db.query(`UPDATE tenancy_agreements SET tenant_signature=$1, tenant_signed_at=NOW() WHERE tenancy_id=$2`, [signature, tenancyId]);
    }

    await logActivity('Tenancy agreement signed by ' + info.role + ' (' + signature + ') for tenancy ' + tenancyId);
    const updated = await db.query('SELECT * FROM tenancy_agreements WHERE tenancy_id=$1', [tenancyId]);
    const ag = updated.rows[0];
    const t = info.tenancy;
    if (ag.owner_signature && ag.tenant_signature) {
      if (t.property_owner_id) createNotification(t.property_owner_id, 'agreement_signed', '✅ Agreement Fully Signed', t.property || '', { tenancy_id: tenancyId }).catch(() => {});
      if (t.tenant_id) createNotification(t.tenant_id, 'agreement_signed', '✅ Agreement Fully Signed', t.property || '', { tenancy_id: tenancyId }).catch(() => {});
    } else {
      const otherUserId = info.role === 'owner' ? t.tenant_id : t.property_owner_id;
      if (otherUserId) createNotification(otherUserId, 'agreement_pending', '📝 Agreement Awaiting Your Signature', t.property || '', { tenancy_id: tenancyId }).catch(() => {});
    }
    json(res, 200, { success: true, agreement: ag });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── Favorites (save/heart a property) ────────────────────────────────────────
// ── Push token registration ───────────────────────────────────────────────
async function handleRegisterPushToken(ownerId, data, res) {
  try {
    const token = data && data.push_token;
    if (!token) return json(res, 400, { error: 'push_token required' });
    await db.query(`ALTER TABLE registrations ADD COLUMN IF NOT EXISTS push_token TEXT`).catch(() => {});
    await db.query('UPDATE registrations SET push_token=$1, updated_at=NOW() WHERE id=$2', [token, ownerId]);
    await logActivity('Push token registered for ' + ownerId + ' (ends …' + token.slice(-8) + ')').catch(() => {});
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function getPushToken(userId) {
  try {
    const r = await db.query('SELECT push_token FROM registrations WHERE id=$1', [userId]);
    return r.rows[0]?.push_token || null;
  } catch(e) { return null; }
}

// ── In-app notification center ───────────────────────────────────────────
// A single place that both stores a real, viewable notification (for the
// previously-empty "Notifications" tab on both platforms) and fires the
// matching push notification — every event type only needs one call here
// to cover both delivery paths instead of wiring push separately everywhere.
async function ensureNotificationsTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL,
    title TEXT NOT NULL, body TEXT DEFAULT '', data JSONB DEFAULT '{}',
    read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
}

async function createNotification(userId, type, title, body, data) {
  if (!userId) return;
  try {
    await ensureNotificationsTable();
    await db.query(
      'INSERT INTO notifications (user_id, type, title, body, data) VALUES ($1,$2,$3,$4,$5)',
      [userId, type, title, body || '', JSON.stringify(data || {})]
    );
    broadcast('notification_new', { user_id: userId });

    // The result of sendPushNotification was previously discarded entirely
    // (.catch(()=>{}) only catches a rejected promise, not a resolved but
    // failed {ok:false} result) - meaning a bad token, malformed request,
    // or FCM error of any kind was completely silent, with no way to tell
    // what was actually wrong. Logs the real outcome to the Activity Log
    // (visible in admin.html) so this is diagnosable without needing
    // Railway's console logs at all.
    const token = await getPushToken(userId);
    if (!token) {
      await logActivity('Push skipped for ' + userId + ' (' + type + '): no device token registered').catch(() => {});
      return;
    }
    const result = await sendPushNotification(token, title, body || '', Object.assign({ type }, data || {}));
    if (result.skipped) {
      await logActivity('Push skipped for ' + userId + ' (' + type + '): ' + (result.reason || 'unknown reason')).catch(() => {});
    } else if (result.ok) {
      await logActivity('Push sent to ' + userId + ' (' + type + ')').catch(() => {});
    } else {
      await logActivity('Push FAILED for ' + userId + ' (' + type + '): status=' + result.status + ' body=' + (result.body || result.error || '').toString().slice(0, 200)).catch(() => {});
    }
  } catch (e) {
    console.error('createNotification failed for user ' + userId + ':', e.message);
    await logActivity('createNotification error for ' + userId + ': ' + e.message).catch(() => {});
  }
}

async function handleGetNotifications(userId, res) {
  try {
    await ensureNotificationsTable();
    const r = await db.query('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [userId]);
    json(res, 200, { success: true, notifications: r.rows });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function handleMarkNotificationsRead(userId, data, res) {
  try {
    await ensureNotificationsTable();
    if (data && data.id) {
      await db.query('UPDATE notifications SET read_at=NOW() WHERE id=$1 AND user_id=$2', [data.id, userId]);
    } else {
      await db.query('UPDATE notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL', [userId]);
    }
    json(res, 200, { success: true });
  } catch (e) { json(res, 500, { error: e.message }); }
}

// ── In-app chat (polling-based -- matches the rest of this app's pattern of
// 30s background refresh rather than websockets) ────────────────────────────
async function ensureMessagesTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    property_id TEXT, sender_id TEXT NOT NULL, recipient_id TEXT NOT NULL,
    sender_name TEXT DEFAULT '', body TEXT NOT NULL,
    read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
  // Which individual support staff member actually sent this, when the
  // sender is the shared SUPPORT_USER_ID account — null for every other
  // message (a real owner or tenant sending as themselves has no need for
  // this, sender_id already identifies them uniquely).
  await db.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_staff_id INTEGER`).catch(() => {});
  await db.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_staff_name TEXT`).catch(() => {});
}

// A "conversation" is just the (other_user, property) pair a message thread
// belongs to -- there's no separate conversations table, it's derived.
async function handleGetConversations(userId, res) {
  try {
    await ensureMessagesTable();
    const r = await db.query(`
      SELECT DISTINCT ON (other_id, property_id) *
      FROM (
        SELECT
          CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END as other_id,
          property_id, body, sender_id, created_at, read_at,
          CASE WHEN recipient_id=$1 AND read_at IS NULL THEN 1 ELSE 0 END as unread
        FROM messages WHERE sender_id=$1 OR recipient_id=$1
      ) t
      ORDER BY other_id, property_id, created_at DESC
    `, [userId]);
    // Enrich with the other party's name and the property title
    const rows = await Promise.all(r.rows.map(async (row) => {
      const [nameR, propR] = await Promise.all([
        db.query('SELECT fname, lname FROM registrations WHERE id=$1', [row.other_id]),
        row.property_id ? db.query('SELECT title FROM properties WHERE id=$1', [row.property_id]) : Promise.resolve({ rows: [] })
      ]);
      const n = nameR.rows[0];
      return {
        other_id: row.other_id,
        other_name: n ? (n.fname + ' ' + n.lname).trim() : 'User',
        property_id: row.property_id,
        property_title: propR.rows[0]?.title || '',
        last_message: row.body, last_at: row.created_at,
        unread: !!row.unread
      };
    }));
    rows.sort((a, b) => new Date(b.last_at) - new Date(a.last_at));
    json(res, 200, { success: true, conversations: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetThread(userId, otherId, propertyId, res) {
  try {
    await ensureMessagesTable();
    const r = await db.query(`
      SELECT * FROM messages
      WHERE ((sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1))
        AND (property_id=$3 OR ($3='' AND property_id IS NULL))
      ORDER BY created_at ASC
    `, [userId, otherId, propertyId || '']);
    // Mark incoming messages as read
    await db.query(`UPDATE messages SET read_at=NOW() WHERE sender_id=$1 AND recipient_id=$2 AND read_at IS NULL AND (property_id=$3 OR ($3='' AND property_id IS NULL))`, [otherId, userId, propertyId || '']);

    // Sent/delivered/read status per message, for the sender's own bubbles
    // (matching the WhatsApp-style single/double/blue-double tick
    // convention — read_at already exists and is set precisely when the
    // recipient opens this thread; "delivered" is a genuine signal too,
    // not a fake middle state — it's true the moment the recipient has
    // been active anywhere in the app since the message was sent, even if
    // they haven't opened this specific thread yet).
    const otherActiveR = await db.query('SELECT last_active_at FROM registrations WHERE id=$1', [otherId]);
    const otherLastActive = otherActiveR.rows[0]?.last_active_at ? new Date(otherActiveR.rows[0].last_active_at) : null;
    const messages = r.rows.map(m => {
      let status = 'sent';
      if (m.read_at) status = 'read';
      else if (otherLastActive && new Date(m.created_at) <= otherLastActive) status = 'delivered';
      return Object.assign({}, m, { status });
    });

    json(res, 200, { success: true, messages });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSendMessage(senderId, data, res, req) {
  try {
    await ensureMessagesTable();
    const { recipient_id, property_id, body, sender_name } = data || {};
    if (!recipient_id || !body || !body.trim()) return json(res, 400, { error: 'recipient_id and body required' });

    // For support-account sends, derive the actual staff attribution from
    // the verified login token rather than the client-supplied sender_name
    // — a client value can't be trusted to say who's really typing, but the
    // TOTP-verified staff id embedded at login can. Every other sender
    // (a real owner or tenant) is unaffected — staffId is simply null.
    let staffId = null, staffName = null;
    if (senderId === SUPPORT_USER_ID && req) {
      staffId = getStaffIdFromToken(req);
      if (staffId) {
        const staffR = await db.query('SELECT name FROM support_staff WHERE id=$1', [staffId]);
        staffName = staffR.rows[0]?.name || null;
      }
    }

    const r = await db.query(
      'INSERT INTO messages (property_id, sender_id, recipient_id, sender_name, body, sender_staff_id, sender_staff_name) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at',
      [property_id || null, senderId, recipient_id, sender_name || '', body.trim(), staffId, staffName]
    );
    json(res, 200, { success: true, id: r.rows[0].id, created_at: r.rows[0].created_at });
    // Best-effort, after responding to the sender — stores a real
    // notification (for the Notifications tab) and pushes, in one call.
    createNotification(recipient_id, 'chat', sender_name || 'New message', body.trim().slice(0, 100), { sender_id: senderId, property_id: property_id || '' }).catch(() => {});
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── Support conversation claims ──────────────────────────────────────────
// The support inbox is shared: any staff member's login authenticates as
// the same SUPPORT_USER_ID, so without this, two people could easily start
// replying to the same customer at once with no way to know the other was
// already there. A "claim" is a deliberate, visible act (not automatic on
// first reply) — one row per customer conversation, showing who's on it.
// Any staff member can release a claim (not just the one who made it), so
// a claim left behind by someone who went offline doesn't lock the
// conversation for everyone else.
async function ensureConversationClaimsTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS conversation_claims (
    customer_id TEXT PRIMARY KEY,
    claimed_by_staff_id INTEGER NOT NULL,
    claimed_by_staff_name TEXT NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
}

async function handleClaimConversation(req, data, res) {
  const staffId = getStaffIdFromToken(req);
  if (!staffId) return json(res, 403, { error: 'Only individually-enrolled support staff can claim conversations' });
  const { customerId } = data || {};
  if (!customerId) return json(res, 400, { error: 'customerId required' });
  try {
    await ensureConversationClaimsTable();
    const staffR = await db.query('SELECT name FROM support_staff WHERE id=$1 AND revoked=false', [staffId]);
    if (!staffR.rows.length) return json(res, 403, { error: 'Staff account not found or revoked' });
    const staffName = staffR.rows[0].name;
    await db.query(
      `INSERT INTO conversation_claims (customer_id, claimed_by_staff_id, claimed_by_staff_name, claimed_at)
       VALUES ($1,$2,$3,NOW())
       ON CONFLICT (customer_id) DO UPDATE SET claimed_by_staff_id=$2, claimed_by_staff_name=$3, claimed_at=NOW()`,
      [customerId, staffId, staffName]
    );
    broadcast('support_claim_changed', { customerId, claimedBy: { staffId, staffName } });
    json(res, 200, { success: true, claimedBy: { staffId, staffName } });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleReleaseConversation(req, data, res) {
  const staffId = getStaffIdFromToken(req);
  if (!staffId) return json(res, 403, { error: 'Only individually-enrolled support staff can release conversations' });
  const { customerId } = data || {};
  if (!customerId) return json(res, 400, { error: 'customerId required' });
  try {
    await ensureConversationClaimsTable();
    await db.query('DELETE FROM conversation_claims WHERE customer_id=$1', [customerId]);
    broadcast('support_claim_changed', { customerId, claimedBy: null });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Ephemeral "someone's viewing this conversation right now" presence — kept
// entirely in the SSE broadcast itself rather than written to the
// database, since presence has no reason to survive a server restart or be
// queried later. Each connected support client sends one of these roughly
// every 10s while a thread is open, and every OTHER connected client clears
// its own "X is viewing" indicator for that conversation if no ping
// arrives for ~20s (handled client-side — see support-app/www/js/app.js).
async function handlePresencePing(req, data, res) {
  const staffId = getStaffIdFromToken(req);
  if (!staffId) return json(res, 403, { error: 'Only individually-enrolled support staff can send presence' });
  const { customerId } = data || {};
  if (!customerId) return json(res, 400, { error: 'customerId required' });
  try {
    const staffR = await db.query('SELECT name FROM support_staff WHERE id=$1', [staffId]);
    const staffName = staffR.rows[0]?.name || 'A staff member';
    broadcast('support_presence', { customerId, staffId, staffName, ts: Date.now() });
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Support-inbox-specific conversation list: the same underlying data as the
// generic handleGetConversations, but enriched with claim status and,
// where the most recent message came from the shared support account,
// which individual staff member actually sent it — neither of which the
// generic customer/owner-facing endpoint has any reason to expose.
async function handleGetSupportConversations(res) {
  try {
    await ensureMessagesTable();
    await ensureConversationClaimsTable();
    const r = await db.query(`
      SELECT DISTINCT ON (other_id, property_id) *
      FROM (
        SELECT
          CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END as other_id,
          property_id, body, sender_id, sender_staff_name, created_at, read_at,
          CASE WHEN recipient_id=$1 AND read_at IS NULL THEN 1 ELSE 0 END as unread
        FROM messages WHERE sender_id=$1 OR recipient_id=$1
      ) t
      ORDER BY other_id, property_id, created_at DESC
    `, [SUPPORT_USER_ID]);
    const claimsR = await db.query('SELECT * FROM conversation_claims');
    const claimsByCustomer = {};
    claimsR.rows.forEach(c => { claimsByCustomer[c.customer_id] = { staffId: c.claimed_by_staff_id, staffName: c.claimed_by_staff_name, claimedAt: c.claimed_at }; });

    const rows = await Promise.all(r.rows.map(async (row) => {
      const [nameR, propR] = await Promise.all([
        db.query('SELECT fname, lname FROM registrations WHERE id=$1', [row.other_id]),
        row.property_id ? db.query('SELECT title FROM properties WHERE id=$1', [row.property_id]) : Promise.resolve({ rows: [] })
      ]);
      const n = nameR.rows[0];
      return {
        other_id: row.other_id,
        other_name: n ? (n.fname + ' ' + n.lname).trim() : 'User',
        property_id: row.property_id,
        property_title: propR.rows[0]?.title || '',
        last_message: row.body, last_at: row.created_at,
        last_message_staff_name: row.sender_id === SUPPORT_USER_ID ? (row.sender_staff_name || null) : null,
        unread: !!row.unread,
        claimedBy: claimsByCustomer[row.other_id] || null
      };
    }));
    rows.sort((a, b) => new Date(b.last_at) - new Date(a.last_at));
    json(res, 200, { success: true, conversations: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function ensureFavoritesTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS favorites (
    user_id TEXT NOT NULL, property_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, property_id)
  )`).catch(() => {});
}

async function handleGetFavorites(ownerId, res) {
  try {
    await ensureFavoritesTable();
    const result = await db.query(`
      SELECT p.id, p.title, p.owner, p.type, COALESCE(p.listing_type,p.type,'rent') as listing_type,
        p.status, p.price, p.state, p.lga, p.address, p.img,
        COALESCE(p.images,'[]'::jsonb) as images, p.nightly_rate, p.annual_rent,
        f.created_at as favorited_at
      FROM favorites f JOIN properties p ON p.id = f.property_id
      WHERE f.user_id = $1 ORDER BY f.created_at DESC
    `, [ownerId]);
    json(res, 200, { success: true, favorites: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleAddFavorite(ownerId, data, res) {
  try {
    await ensureFavoritesTable();
    const propertyId = data && data.property_id;
    if (!propertyId) return json(res, 400, { error: 'property_id required' });
    await db.query(
      'INSERT INTO favorites (user_id, property_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [ownerId, propertyId]
    );
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleRemoveFavorite(ownerId, propertyId, res) {
  try {
    await ensureFavoritesTable();
    await db.query('DELETE FROM favorites WHERE user_id=$1 AND property_id=$2', [ownerId, propertyId]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── Saved Searches (in-app matching for now; push alerts are a later phase) ──
async function ensureSavedSearchesTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS saved_searches (
    id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, label TEXT DEFAULT '',
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
}

async function handleGetSavedSearches(ownerId, res) {
  try {
    await ensureSavedSearchesTable();
    const result = await db.query(
      'SELECT id, label, filters, created_at FROM saved_searches WHERE user_id=$1 ORDER BY created_at DESC',
      [ownerId]
    );
    json(res, 200, { success: true, searches: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleAddSavedSearch(ownerId, data, res) {
  try {
    await ensureSavedSearchesTable();
    const { label, filters } = data || {};
    if (!filters || typeof filters !== 'object') return json(res, 400, { error: 'filters object required' });
    const result = await db.query(
      'INSERT INTO saved_searches (user_id, label, filters) VALUES ($1,$2,$3) RETURNING id',
      [ownerId, label || '', JSON.stringify(filters)]
    );
    json(res, 200, { success: true, id: result.rows[0].id });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleRemoveSavedSearch(ownerId, searchId, res) {
  try {
    await ensureSavedSearchesTable();
    await db.query('DELETE FROM saved_searches WHERE id=$1 AND user_id=$2', [searchId, ownerId]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Notifies every saved-search owner whose filters match a listing that just
// went live for the first time. Only matches on type/state (see the caller
// in handleAdminUpdate for why filters.q — free text — isn't used here).
// Deduped per user in case someone has multiple searches that all match the
// same property, and never notifies the property's own owner about their
// own listing.
async function notifySavedSearchMatches(propertyId) {
  await ensureSavedSearchesTable();
  const propR = await db.query(
    "SELECT title, owner_id, COALESCE(listing_type,type,'rent') as listing_type, state FROM properties WHERE id=$1",
    [propertyId]
  );
  const prop = propR.rows[0];
  if (!prop) return;
  const searches = await db.query('SELECT user_id, filters FROM saved_searches');
  const matchedUserIds = new Set();
  for (const s of searches.rows) {
    let filters = s.filters;
    if (typeof filters === 'string') { try { filters = JSON.parse(filters); } catch (e) { filters = {}; } }
    filters = filters || {};
    const typeMatches = !filters.type || filters.type === 'all' || filters.type === prop.listing_type;
    const stateMatches = !filters.state || filters.state === prop.state;
    if (typeMatches && stateMatches && s.user_id !== prop.owner_id) matchedUserIds.add(s.user_id);
  }
  for (const userId of matchedUserIds) {
    createNotification(userId, 'saved_search_match', '🔔 New Listing Matches Your Search', prop.title, { property_id: propertyId }).catch(() => {});
  }
}

// ── Ratings ───────────────────────────────────────────────────────────────
// Default design (flagged for the person to redirect if they want something
// different): rates the OWNER after a transaction, 1-5 stars + optional
// comment, publicly visible (aggregated average + count) on their listings —
// same pattern as Airbnb/Jumia reviews. One rating per (rater, owner, ref)
// so the same completed transaction can't be rated twice.
async function ensureRatingsTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS ratings (
    id SERIAL PRIMARY KEY, rater_id TEXT NOT NULL, owner_id TEXT NOT NULL,
    ref TEXT, stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
    comment TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(rater_id, owner_id, ref)
  )`).catch(() => {});
}

async function handleAddRating(ownerId, data, res) {
  try {
    await ensureRatingsTable();
    const { owner_id, ref, stars, comment } = data || {};
    if (!owner_id) return json(res, 400, { error: 'owner_id required' });
    const s = Number(stars);
    if (!s || s < 1 || s > 5) return json(res, 400, { error: 'stars must be 1-5' });
    await db.query(
      `INSERT INTO ratings (rater_id, owner_id, ref, stars, comment) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (rater_id, owner_id, ref) DO UPDATE SET stars=$4, comment=$5`,
      [ownerId, owner_id, ref || '', s, comment || '']
    );
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetOwnerRatings(ownerId, res) {
  try {
    await ensureRatingsTable();
    const result = await db.query(
      `SELECT stars, comment, created_at FROM ratings WHERE owner_id=$1 ORDER BY created_at DESC`,
      [ownerId]
    );
    const rows = result.rows;
    const avg = rows.length ? rows.reduce((s,r) => s + r.stars, 0) / rows.length : 0;
    json(res, 200, { success: true, average: Math.round(avg*10)/10, count: rows.length, ratings: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleAdminUpdate(url, data, res) {
  const regMatch = url.match(/^\/admin\/registration\/([^/]+)$/);
  if (regMatch) {
    const id = regMatch[1];
    const { status, reviewer, notes } = data;
    try {
      const before = await db.query('SELECT status, fname FROM registrations WHERE id=$1', [id]);
      const prevStatus = before.rows[0]?.status;
      await db.query(
        'UPDATE registrations SET status=$1, reviewer=$2, notes=$3, updated_at=NOW() WHERE id=$4',
        [status, reviewer||'Admin', notes||'', id]
      );
      // Previously scoped to role='owner' only, so a regular renter/buyer
      // getting their identity approved never actually got is_verified set
      // true - login's response reads verified: user.is_verified for any
      // role, so this silently broke verification for every non-owner
      // customer, not just an owner-specific edge case.
      if (status === 'approved') {
        try {
          await db.query('UPDATE registrations SET is_verified=true WHERE id=$1', [id]);
        } catch(verifyErr) {
          try {
            await db.query("ALTER TABLE registrations ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE");
            await db.query("ALTER TABLE registrations ADD COLUMN IF NOT EXISTS owner_since TIMESTAMPTZ");
            await db.query('UPDATE registrations SET is_verified=true WHERE id=$1', [id]);
          } catch(e2) { console.warn('is_verified column fix failed:', e2.message); }
        }
      }
      await logActivity('Registration ' + status + ': ' + id);
      broadcast('registration_updated', { id, status });
      json(res, 200, { success: true });

      // Notify the customer the moment their identity is actually approved
      // (a genuine transition, not on every subsequent notes/reviewer edit) -
      // previously nothing told them at all; they'd only find out by
      // re-checking the app themselves.
      if (status === 'approved' && status !== prevStatus) {
        createNotification(id, 'identity_verified', '✅ Identity Verified', "You're now a verified GeoEstate member.", {}).catch(() => {});
      }
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  const propMatch = url.match(/^\/admin\/property\/([^/]+)$/);
  if (propMatch) {
    const id = propMatch[1];
    try {
      const before = await db.query("SELECT status FROM properties WHERE id=$1", [id]);
      const wasLive = before.rows[0]?.status === 'live';
      if (data.site_visit_verified !== undefined || data.site_visit_date !== undefined || data.site_visit_notes !== undefined) {
        await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_verified BOOLEAN DEFAULT FALSE`).catch(() => {});
        await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_date DATE`).catch(() => {});
        await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_notes TEXT DEFAULT ''`).catch(() => {});
      }
      const allowed = ['title','owner','listing_type','type','status','price','monthly_rent','sale_price','lease_price','state','lga','address','img','images','bedrooms','bathrooms','size_sqm','description','amenities','notes','lawyer_assigned','geo','site_visit_verified','site_visit_date','site_visit_notes'];
      const fields = Object.entries(data).filter(([k]) => allowed.includes(k));
      if (!fields.length) return json(res, 400, { error: 'No valid fields' });
      const sets = fields.map(([k],i) => `${k}=$${i+2}`).join(',');
      await db.query(`UPDATE properties SET ${sets},updated_at=NOW() WHERE id=$1`, [id, ...fields.map(([,v])=>v)]);
      await logActivity('Property updated: ' + id);
      broadcast('property_updated', { id });
      json(res, 200, { success: true });

      // Notify saved-search owners the moment a listing genuinely goes live
      // for the first time (not on every subsequent edit to an already-live
      // listing). Only matches on type/state — filters.q (free-text) is
      // deliberately not used for matching here, since substring-matching a
      // search query against a title is unreliable and this is meant as a
      // helpful nudge, not a precise search engine.
      if (data.status === 'live' && !wasLive) {
        notifySavedSearchMatches(id).catch(e => console.error('notifySavedSearchMatches failed:', e.message));
      }
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
      // Fetch the row first so we can tell whether this is a genuine
      // transition into 'contacted' (only notify once, not on every
      // subsequent notes/assigned_to edit) and so we have the enquirer's
      // email + property title on hand afterward.
      const before = await db.query('SELECT status, email, property_title FROM enquiries WHERE id=$1', [id]);
      const prevStatus = before.rows[0]?.status;
      await db.query(
        'UPDATE enquiries SET status=COALESCE($1,status), notes=COALESCE($2,notes), assigned_to=COALESCE($3,assigned_to) WHERE id=$4',
        [status||null, notes||null, assigned_to||null, id]
      );
      await logActivity('Enquiry ' + id + ' updated → ' + (status||'no status change'));
      broadcast('enquiry_updated', { id, status });
      json(res, 200, { success: true });

      // Enquiries aren't tied to a registered account (name/email/phone are
      // free-text — someone can enquire without ever signing up), so this
      // can only notify if the enquirer's email happens to match one.
      if (status === 'contacted' && status !== prevStatus && before.rows[0]?.email) {
        const propertyTitle = before.rows[0].property_title || 'your enquiry';
        db.query('SELECT id FROM registrations WHERE email=$1', [before.rows[0].email]).then(r => {
          const enquirerId = r.rows[0]?.id;
          if (enquirerId) createNotification(enquirerId, 'enquiry_replied', '📬 Enquiry Update', 'Our team has followed up on your enquiry about ' + propertyTitle, { enquiry_id: id }).catch(() => {});
        }).catch(() => {});
      }
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }


  json(res, 404, { error: 'Unknown admin update endpoint' });
}

async function handleSaveProperty(data, res) {
  const { id, title, owner, owner_id, listing_type, type, status, price, monthly_rent, sale_price, lease_price, state, lga, address, img, images, bedrooms, bathrooms, size_sqm, description, amenities, notes, lat, lng, geo } = data;
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
      // lat/lng/geo (map pin) — admin edit form's "Location (Map Pin)" fields
      // were silently dropped on create because this insert never wrote them.
      if (lat != null || lng != null) {
        await db.query(
          `UPDATE properties SET lat=$1,lng=$2,geo=$3 WHERE id=$4`,
          [lat!=null ? Number(lat) : null, lng!=null ? Number(lng) : null, !!geo, propId]
        ).catch(()=>{});
      }
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

// Shared by both manual tenancy entry (handleSaveTenancy) and automatic
// tenancy creation on payment confirmation (handleSavePayment) — one place
// for the actual INSERT + occupied-unit side effect, so both paths stay
// in sync and neither can silently drift from the other.
async function createTenancyRecord(t) {
  const { ref, type, property, property_id, unit_id, tenant, tenant_id, phone, owner, amount, start, end, notes } = t;
  if (!property || !tenant || !end) throw new Error('Property, tenant and end date required');
  await db.query(
    `INSERT INTO tenancies (ref,type,property,property_id,unit_id,tenant,tenant_id,phone,owner,amount,start_date,end_date,notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     ON CONFLICT (ref) DO NOTHING`,
    [ref||('TEN-'+Date.now()),type||'rent',property,property_id||null,unit_id||null,tenant,tenant_id||null,phone||'',owner||'',amount||0,start,end,notes||'']
  );
  if (unit_id) {
    await db.query("UPDATE property_units SET status='occupied', current_tenant_id=$1, occupied_since=$2, lease_end=$3 WHERE id=$4",
      [tenant_id||null, start, end, unit_id]);
  }
  await logActivity('Tenancy added: ' + (ref||'') + ' — ' + property);
  broadcast('tenancy_created', { property });
}

async function handleSaveTenancy(data, res) {
  try {
    await createTenancyRecord(data);
    json(res, 200, { success: true });
  } catch(e) { json(res, e.message.includes('required') ? 400 : 500, { error: e.message }); }
}

// Removes a property from public/live listing once it's no longer available
// — but for a multi-unit property, only once EVERY unit has been taken.
// A single vacant room/flat should keep the whole property visible (with
// that unit correctly marked occupied on its own card); the property itself
// only comes down once there's nothing left for a customer to select.
// listingType decides the terminal status: 'sold' for buy, 'completed' for
// rent/lease — both already recognized by admin.html's Manage Properties
// view (it already filters on exactly these two values).
async function maybeDelistProperty(propertyId, listingType) {
  try {
    const unitsR = await db.query(
      "SELECT COUNT(*)::int as total, COUNT(*) FILTER (WHERE status='vacant')::int as vacant FROM property_units WHERE property_id=$1",
      [propertyId]
    );
    const { total, vacant } = unitsR.rows[0];
    if (total > 0 && vacant > 0) return; // still has at least one vacant unit — keep it live
    const terminalStatus = listingType === 'buy' ? 'sold' : 'completed';
    const r = await db.query("UPDATE properties SET status=$1, updated_at=NOW() WHERE id=$2 AND status='live' RETURNING id", [terminalStatus, propertyId]);
    if (r.rows.length) {
      await logActivity('Property ' + propertyId + ' automatically delisted as ' + terminalStatus + (total > 0 ? ' (all units taken)' : ''));
      broadcast('property_updated', { id: propertyId, status: terminalStatus });
    }
  } catch (e) {
    console.error('maybeDelistProperty failed for ' + propertyId + ':', e.message);
  }
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

// ── Geospatial consulting leads (GeoEstate Spatial Intelligence site) ───────
// Public inbound lead form - separate business line from the property
// marketplace, but reuses this same backend's DB/email infrastructure
// rather than needing its own server, matching how /submit-dispute and
// /submit-property already work as public POST endpoints with no auth.
async function ensureGeospatialLeadsTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS geospatial_leads (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT,
    organization TEXT, services TEXT, message TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
}

function geospatialLeadNotifyEmail(lead) {
  return `
    <div style="font-family:sans-serif;max-width:560px">
      <h2 style="color:#0f1b2e">New Geospatial Consulting Lead</h2>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:6px 0;color:#5c6b7a;width:120px">Name</td><td style="padding:6px 0"><strong>${lead.name}</strong></td></tr>
        <tr><td style="padding:6px 0;color:#5c6b7a">Email</td><td style="padding:6px 0">${lead.email}</td></tr>
        <tr><td style="padding:6px 0;color:#5c6b7a">Phone</td><td style="padding:6px 0">${lead.phone || '—'}</td></tr>
        <tr><td style="padding:6px 0;color:#5c6b7a">Organization</td><td style="padding:6px 0">${lead.organization || '—'}</td></tr>
        <tr><td style="padding:6px 0;color:#5c6b7a;vertical-align:top">Services</td><td style="padding:6px 0">${lead.services || '—'}</td></tr>
      </table>
      <div style="margin-top:16px;padding:14px;background:#f5f4f0;border-radius:6px;font-size:14px;color:#0f1b2e;white-space:pre-wrap">${(lead.message || '(no message provided)').replace(/</g,'&lt;')}</div>
    </div>
  `;
}

function geospatialLeadConfirmEmail(lead) {
  return `
    <div style="font-family:sans-serif;max-width:560px">
      <h2 style="color:#0f1b2e">Thanks, ${lead.name.split(' ')[0]} — we've got your request</h2>
      <p style="color:#5c6b7a;font-size:14px;line-height:1.6">Someone from GeoEstate Spatial Intelligence will follow up within one business day to scope your project. If it's urgent, you can also reach us directly at +234 916 042 0100.</p>
      <p style="color:#5c6b7a;font-size:14px;line-height:1.6">— GeoEstate Spatial Intelligence, a division of GeoEstate NIG Limited</p>
    </div>
  `;
}

async function handleGeospatialLead(data, res) {
  const { name, email, phone, organization, services, message } = data;
  if (!name || !email) return json(res, 400, { error: 'Name and email are required' });
  try {
    await ensureGeospatialLeadsTable();
    const servicesStr = Array.isArray(services) ? services.join(', ') : (services || '');
    await db.query(
      'INSERT INTO geospatial_leads (name, email, phone, organization, services, message) VALUES ($1,$2,$3,$4,$5,$6)',
      [name, email, phone || '', organization || '', servicesStr, message || '']
    );
    await logActivity('Geospatial consulting lead: ' + name + (organization ? ' (' + organization + ')' : '')).catch(() => {});
    const leadData = { name, email, phone, organization, services: servicesStr, message };
    if (ADMIN_EMAIL) sendEmail(ADMIN_EMAIL, 'New Geospatial Consulting Lead: ' + name, geospatialLeadNotifyEmail(leadData)).catch(() => {});
    sendEmail(email, "We've received your request — GeoEstate Spatial Intelligence", geospatialLeadConfirmEmail(leadData)).catch(() => {});
    json(res, 200, { success: true });
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

// ── Payment confirmed / released email templates ────────────────────────────
function paymentConfirmedEmail(p, forOwner) {
  const heading = forOwner ? '✅ Payment Confirmed — Handover Can Proceed' : '✅ Your Payment Has Been Confirmed';
  const intro = forOwner
    ? `GeoEstate has confirmed receipt of the buyer/tenant's transfer for <strong>${p.prop}</strong>. You can now proceed with handover. Funds (minus platform fee) will be released to your account shortly.`
    : `Good news — we've confirmed your transfer for <strong>${p.prop}</strong>. You can now coordinate handover with the owner/GeoEstate team.`;
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:520px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:24px 32px">
  <div style="color:#fff;font-size:18px;font-weight:800">📍 ${heading}</div>
  <div style="color:rgba(255,255,255,.65);font-size:13px;margin-top:4px">Reference ${p.ref}</div>
</td></tr>
<tr><td style="padding:32px">
  <p style="color:#374151;font-size:14px;line-height:1.6">${intro}</p>
  <table style="width:100%;font-size:14px;border-collapse:collapse;background:#f0fdf4;border-radius:8px;padding:12px;margin-top:8px">
    <tr><td style="padding:6px 12px;color:#6b7280">Property</td><td style="padding:6px 12px;font-weight:700">${p.prop}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">${forOwner ? 'Buyer/Tenant' : 'Owner'}</td><td style="padding:6px 12px">${forOwner ? p.buyer : p.owner}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">Amount Paid</td><td style="padding:6px 12px;font-weight:700">₦${Number(p.amount||0).toLocaleString('en-NG')}</td></tr>
    ${forOwner ? `<tr><td style="padding:6px 12px;color:#6b7280">You'll Receive</td><td style="padding:6px 12px;font-weight:700;color:#1a6b3c">₦${Number(p.owner_amt||0).toLocaleString('en-NG')}</td></tr>` : ''}
  </table>
</td></tr>
</table></td></tr></table></body></html>`;
}

function paymentReleasedEmail(p) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:520px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:24px 32px">
  <div style="color:#fff;font-size:18px;font-weight:800">💸 Funds Released to Your Account</div>
  <div style="color:rgba(255,255,255,.65);font-size:13px;margin-top:4px">Reference ${p.ref}</div>
</td></tr>
<tr><td style="padding:32px">
  <p style="color:#374151;font-size:14px;line-height:1.6">GeoEstate has released your payout for <strong>${p.prop}</strong>. Please allow up to 24 hours for the transfer to reflect in your bank account.</p>
  <table style="width:100%;font-size:14px;border-collapse:collapse;background:#f0fdf4;border-radius:8px;padding:12px;margin-top:8px">
    <tr><td style="padding:6px 12px;color:#6b7280">Property</td><td style="padding:6px 12px;font-weight:700">${p.prop}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">Amount Released</td><td style="padding:6px 12px;font-weight:700;color:#1a6b3c">₦${Number(p.owner_amt||0).toLocaleString('en-NG')}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">Platform Fee (10%)</td><td style="padding:6px 12px">₦${Number(p.fee||0).toLocaleString('en-NG')}</td></tr>
  </table>
</td></tr>
</table></td></tr></table></body></html>`;
}

function tenancyReminderEmail(t, stage, forOwner) {
  const stageCopy = {
    two_month: {
      heading: '📅 Tenancy Renewal — 2 Months Notice',
      tenant: `Your ${t.type} agreement for <strong>${t.property}</strong> is due to end on <strong>${new Date(t.end_date).toLocaleDateString('en-NG',{day:'numeric',month:'long',year:'numeric'})}</strong>. Please confirm whether you'd like to renew, or give notice to vacate.`,
      owner: `A tenancy on your property <strong>${t.property}</strong> is entering its 2-month renewal window (ends ${new Date(t.end_date).toLocaleDateString('en-NG',{day:'numeric',month:'long',year:'numeric'})}). The tenant has been notified to confirm renewal or give notice.`
    },
    two_week: {
      heading: '⏰ Final Reminder — Tenancy Ends in 2 Weeks',
      tenant: `This is a final reminder that your ${t.type} agreement for <strong>${t.property}</strong> ends on <strong>${new Date(t.end_date).toLocaleDateString('en-NG',{day:'numeric',month:'long',year:'numeric'})}</strong>. If no renewal payment is made, the packing-out process will begin on expiry.`,
      owner: `A tenancy on <strong>${t.property}</strong> is 2 weeks from expiry with no renewal confirmed yet. If nothing changes, the packing-out process begins automatically on the end date.`
    },
    expiry: {
      heading: '📦 Tenancy Ended — Packing-Out Period Begins',
      tenant: `Your ${t.type} agreement for <strong>${t.property}</strong> ended on <strong>${new Date(t.end_date).toLocaleDateString('en-NG',{day:'numeric',month:'long',year:'numeric'})}</strong>. As outlined in our policy, you have <strong>3 weeks</strong> from today to vacate the property unless a renewal has already been arranged.`,
      owner: `A tenancy on <strong>${t.property}</strong> has reached its end date. The tenant has been notified of the standard 3-week packing-out period, per policy.`
    }
  };
  const copy = stageCopy[stage];
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 20px"><tr><td align="center">
<table width="100%" style="max-width:520px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
<tr><td style="background:linear-gradient(135deg,#0d3d22,#1a6b3c);padding:24px 32px">
  <div style="color:#fff;font-size:18px;font-weight:800">${copy.heading}</div>
  <div style="color:rgba(255,255,255,.65);font-size:13px;margin-top:4px">Reference ${t.ref}</div>
</td></tr>
<tr><td style="padding:32px">
  <p style="color:#374151;font-size:14px;line-height:1.6">${forOwner ? copy.owner : copy.tenant}</p>
  <table style="width:100%;font-size:14px;border-collapse:collapse;background:#f0fdf4;border-radius:8px;padding:12px;margin-top:8px">
    <tr><td style="padding:6px 12px;color:#6b7280">Property</td><td style="padding:6px 12px;font-weight:700">${t.property}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">${forOwner ? 'Tenant' : 'Owner'}</td><td style="padding:6px 12px">${forOwner ? t.tenant : t.owner}</td></tr>
    <tr><td style="padding:6px 12px;color:#6b7280">End Date</td><td style="padding:6px 12px;font-weight:700">${new Date(t.end_date).toLocaleDateString('en-NG',{day:'numeric',month:'long',year:'numeric'})}</td></tr>
  </table>
</td></tr>
</table></td></tr></table></body></html>`;
}

// ── Scheduled tenancy renewal/packing-out reminders ──────────────────────
// Implements the exact policy already described (but never actually
// automated) in the admin Tenancy Tracker UI: notify at 2 months before
// expiry, a final reminder at 2 weeks, and an expiry notice starting the
// 3-week packing-out period. Each stage only ever fires once per tenancy,
// tracked via the reminder_*_sent columns.
// Creates the shared "GeoEstate Support" account on boot if it doesn't
// already exist yet — idempotent (ON CONFLICT on the unique email column),
// safe to run on every restart. Pre-approved and pre-verified since it's
// not a real individual going through the normal review flow.
// ── TOTP (RFC 6238) — authenticator app login for the shared support inbox ──
// Implemented directly against Node's built-in crypto (HMAC-SHA1) rather
// than pulling in a library — this is a small, well-specified standard
// algorithm (the same one behind Google Authenticator, Authy, Microsoft
// Authenticator, 1Password, etc.), and one fewer new dependency to trust
// this close to launch.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = '', output = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substr(i, 5).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  return output;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160-bit secret, standard strength
}

// otpauth:// URI that authenticator apps read via QR code — issuer/label
// are what shows up in the app's UI.
function totpKeyUri(secret, email) {
  const issuer = encodeURIComponent('GeoEstate Support');
  const label = encodeURIComponent('GeoEstate Support:' + email);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

function hotpCode(secretBuffer, counter) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binCode % 1000000).padStart(6, '0');
}

// Accepts the current 30s window and one step either side, so a code
// generated just before/after a window boundary (or minor clock drift
// between the phone and the server) still verifies correctly.
function verifyTotpCode(secretBase32, code) {
  if (!code || !/^\d{6}$/.test(code)) return false;
  const secretBuffer = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let drift = -1; drift <= 1; drift++) {
    if (hotpCode(secretBuffer, counter + drift) === code) return true;
  }
  return false;
}

// ── Support staff TOTP enrollment & login ────────────────────────────────
// 4 (or however many) individually-enrolled staff members can each log
// into the SAME shared "GeoEstate Support" inbox using their own
// authenticator app code, instead of everyone sharing one email+OTP.
// Deliberately doesn't touch the chat/messages model at all — a
// successful TOTP login just issues the exact same owner:SUPPORT-001:...
// token every other login path already produces, so every existing
// endpoint (conversations, messages, push, etc.) keeps working unchanged.
async function ensureSupportStaffTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS support_staff (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    totp_secret TEXT NOT NULL, revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_login_at TIMESTAMPTZ,
    setup_token TEXT, setup_token_expires_at TIMESTAMPTZ
  )`).catch(() => {});
  // Self-heals an already-existing table from before these columns existed.
  await db.query(`ALTER TABLE support_staff ADD COLUMN IF NOT EXISTS setup_token TEXT`).catch(() => {});
  await db.query(`ALTER TABLE support_staff ADD COLUMN IF NOT EXISTS setup_token_expires_at TIMESTAMPTZ`).catch(() => {});
}

// A random, unguessable link the admin can send directly to a staff member
// (WhatsApp, email, SMS) instead of requiring them to be physically present
// to scan a QR code — some authenticator apps (Microsoft Authenticator,
// notably) don't reliably support tapping a raw otpauth:// link to add an
// account, so this shows both the QR code AND the manual-entry key as
// plain text, which every authenticator app supports identically. Valid
// for 7 days, not single-use-on-view (so a dropped connection while the
// page loads isn't a dead end) — if it needs to be invalidated early,
// generating a new one (enroll/regenerate again) overwrites it.
function buildStaffSetupUrl(token) {
  return 'https://www.geoestate.com.ng/staff-setup.html?token=' + token;
}

async function handleAddSupportStaff(data, res) {
  const { name, email } = data || {};
  if (!name || !email) return json(res, 400, { error: 'name and email required' });
  try {
    await ensureSupportStaffTable();
    const secret = generateTotpSecret();
    const setupToken = crypto.randomBytes(24).toString('hex');
    const r = await db.query(
      `INSERT INTO support_staff (name, email, totp_secret, setup_token, setup_token_expires_at)
       VALUES ($1,$2,$3,$4,NOW() + INTERVAL '7 days')
       ON CONFLICT (email) DO UPDATE SET totp_secret=$3, revoked=false, setup_token=$4, setup_token_expires_at=NOW() + INTERVAL '7 days'
       RETURNING id`,
      [name.trim(), email.trim().toLowerCase(), secret, setupToken]
    );
    await logActivity('Support staff enrolled: ' + name + ' (' + email + ')').catch(() => {});
    // Secret/URI only ever returned here, at enrollment — never in the
    // list endpoint below, so it can't leak just by viewing staff later.
    json(res, 200, { success: true, id: r.rows[0].id, secret, otpauth_uri: totpKeyUri(secret, email), setup_url: buildStaffSetupUrl(setupToken) });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function handleRegenerateSupportStaff(id, res) {
  try {
    await ensureSupportStaffTable();
    const secret = generateTotpSecret();
    const setupToken = crypto.randomBytes(24).toString('hex');
    const r = await db.query(
      `UPDATE support_staff SET totp_secret=$1, revoked=false, setup_token=$2, setup_token_expires_at=NOW() + INTERVAL '7 days' WHERE id=$3 RETURNING email, name`,
      [secret, setupToken, id]
    );
    if (!r.rows.length) return json(res, 404, { error: 'Staff member not found' });
    await logActivity('Support staff credential reset: ' + r.rows[0].name).catch(() => {});
    json(res, 200, { success: true, secret, otpauth_uri: totpKeyUri(secret, r.rows[0].email), setup_url: buildStaffSetupUrl(setupToken) });
  } catch (e) { json(res, 500, { error: e.message }); }
}

// Public — the staff member opens this (via the link the admin sent them)
// on their own phone, no admin auth involved. Returns everything the
// enrollment modal would have shown in person.
async function handleGetStaffSetup(token, res) {
  try {
    await ensureSupportStaffTable();
    const r = await db.query(
      `SELECT name, email, totp_secret FROM support_staff WHERE setup_token=$1 AND setup_token_expires_at > NOW() AND revoked=false`,
      [token]
    );
    if (!r.rows.length) return json(res, 404, { error: 'This setup link has expired or is no longer valid — ask an admin to send you a new one.' });
    const staff = r.rows[0];
    json(res, 200, { success: true, name: staff.name, email: staff.email, secret: staff.totp_secret, otpauth_uri: totpKeyUri(staff.totp_secret, staff.email) });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function handleListSupportStaff(res) {
  try {
    await ensureSupportStaffTable();
    const r = await db.query('SELECT id, name, email, revoked, created_at, last_login_at FROM support_staff ORDER BY created_at ASC');
    json(res, 200, { success: true, staff: r.rows });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function handleRevokeSupportStaff(id, res) {
  try {
    await ensureSupportStaffTable();
    const r = await db.query('UPDATE support_staff SET revoked=true WHERE id=$1 RETURNING name', [id]);
    if (!r.rows.length) return json(res, 404, { error: 'Staff member not found' });
    await logActivity('Support staff access revoked: ' + r.rows[0].name).catch(() => {});
    json(res, 200, { success: true });
  } catch (e) { json(res, 500, { error: e.message }); }
}

// The actual login — public endpoint (this IS how a staff member logs in),
// verified against their own enrolled secret, then issues a token for the
// shared SUPPORT_USER_ID identity (so every existing chat endpoint keeps
// working completely unchanged) plus an embedded ":s<staffId>" suffix that
// only requireOwner and getStaffIdFromToken know to look for — this is what
// lets claims/attribution/presence identify the individual staff member
// behind a shared login, without touching anything else that authenticates.
async function handleSupportStaffLogin(data, res) {
  const { email, code } = data || {};
  if (!email || !code) return json(res, 400, { error: 'email and code required' });
  try {
    await ensureSupportStaffTable();
    const r = await db.query('SELECT * FROM support_staff WHERE email=$1 AND revoked=false', [email.trim().toLowerCase()]);
    if (!r.rows.length) return json(res, 401, { error: 'Not an enrolled support staff email' });
    const staff = r.rows[0];
    if (!verifyTotpCode(staff.totp_secret, String(code).trim())) {
      return json(res, 401, { error: 'Incorrect or expired code' });
    }
    await db.query('UPDATE support_staff SET last_login_at=NOW() WHERE id=$1', [staff.id]);
    const supportR = await db.query('SELECT * FROM registrations WHERE id=$1', [SUPPORT_USER_ID]);
    const owner = supportR.rows[0] || { id: SUPPORT_USER_ID, fname: 'GeoEstate', lname: 'Support', email: SUPPORT_EMAIL };
    const token = 'owner:' + SUPPORT_USER_ID + ':' + Date.now() + ':s' + staff.id;
    await logActivity('Support staff login: ' + staff.name).catch(() => {});
    json(res, 200, { success: true, token, owner, staff_name: staff.name, staff_id: staff.id });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function ensureSupportAccount() {
  try {
    await db.query(
      `INSERT INTO registrations (id, fname, lname, email, phone, role, type, status, is_verified, reviewer, notes)
       VALUES ($1, 'GeoEstate', 'Support', $2, '', 'owner', 'owner', 'approved', true, 'System', 'Shared support inbox — customers chat with this account instead of a property owner directly.')
       ON CONFLICT (email) DO NOTHING`,
      [SUPPORT_USER_ID, SUPPORT_EMAIL]
    );
  } catch (e) {
    console.error('ensureSupportAccount failed:', e.message);
  }
}

// last_active_at powers chat "delivered" status (see requireOwner) — ensured
// once at boot rather than on every request via ALTER ... IF NOT EXISTS.
async function ensureLastActiveColumn() {
  try {
    await db.query(`ALTER TABLE registrations ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ`);
  } catch (e) {
    console.error('ensureLastActiveColumn failed:', e.message);
  }
}

async function checkTenancyReminders() {
  try {
    const r = await db.query(`
      SELECT t.*, p.owner_id as prop_owner_id,
        (SELECT email FROM registrations WHERE id = t.tenant_id) as tenant_email,
        (SELECT email FROM registrations WHERE id = p.owner_id) as owner_email
      FROM tenancies t
      LEFT JOIN properties p ON p.id = t.property_id
      WHERE t.status = 'active' AND t.end_date IS NOT NULL
    `);
    const now = new Date();
    const stageTitle = {
      two_month: '📅 Renewal — 2 Months Notice',
      two_week: '⏰ Final Reminder — 2 Weeks Left',
      expiry: '📦 Tenancy Ended — Packing-Out Begins'
    };
    for (const t of r.rows) {
      const daysLeft = Math.ceil((new Date(t.end_date) - now) / (1000 * 60 * 60 * 24));
      let stage = null, newStatus = null;
      if (daysLeft <= 0 && !t.reminder_expiry_sent) { stage = 'expiry'; newStatus = 'packing-out'; }
      else if (daysLeft <= 14 && daysLeft > 0 && !t.reminder_2wk_sent) { stage = 'two_week'; }
      else if (daysLeft <= 60 && daysLeft > 14 && !t.reminder_2mo_sent) { stage = 'two_month'; }
      if (!stage) continue;

      if (t.tenant_email) sendEmail(t.tenant_email, 'GeoEstate — ' + t.property, tenancyReminderEmail(t, stage, false)).catch(e => console.warn('Tenant reminder email failed:', e.message));
      if (t.owner_email) sendEmail(t.owner_email, 'GeoEstate — ' + t.property, tenancyReminderEmail(t, stage, true)).catch(e => console.warn('Owner reminder email failed:', e.message));
      if (t.tenant_id) createNotification(t.tenant_id, 'tenancy_reminder', stageTitle[stage], t.property, { ref: t.ref, stage }).catch(() => {});
      if (t.prop_owner_id) createNotification(t.prop_owner_id, 'tenancy_reminder', stageTitle[stage], t.property, { ref: t.ref, stage }).catch(() => {});

      const col = stage === 'expiry' ? 'reminder_expiry_sent' : stage === 'two_week' ? 'reminder_2wk_sent' : 'reminder_2mo_sent';
      await db.query(
        `UPDATE tenancies SET ${col}=TRUE${newStatus ? ", status=$2, packing_out_date=COALESCE(packing_out_date, CURRENT_DATE)" : ""} WHERE id=$1`,
        newStatus ? [t.id, newStatus] : [t.id]
      );
      await logActivity('Tenancy reminder (' + stage + ') sent for ' + t.property + ' — ' + t.ref);
    }
  } catch (e) {
    console.error('checkTenancyReminders failed:', e.message);
  }
}


async function getPropertyOwnerEmail(propertyId) {
  if (!propertyId) return null;
  try {
    const r = await db.query(
      `SELECT (SELECT email FROM registrations WHERE id=properties.owner_id) as owner_email FROM properties WHERE id=$1`,
      [propertyId]
    );
    return r.rows[0]?.owner_email || null;
  } catch(e) { return null; }
}


async function handleGetPayments(res) {
  try {
    await ensureAgreementsTable();
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS handover_confirmed_at TIMESTAMPTZ`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS handover_confirmed_by TEXT`).catch(() => {});
    // Joins in agreement signing status + owner-supplied bank details
    // (captured at signing — see handleSignTenancyAgreement) right on each
    // payment row, so admin/sales can see readiness-to-release without a
    // separate lookup per payment. Tenancy ref is always 'TEN-FROM-' + the
    // payment ref (see createTenancyRecord's caller) — a plain string
    // match, not a stored foreign key, so this is a LEFT JOIN rather than
    // an inner one: payments with no auto-created tenancy (e.g. a 'buy'
    // transaction, which never creates one) still return normally, just
    // with these fields null.
    const r = await db.query(`
      SELECT p.*,
        t.id as resolved_tenancy_id,
        ta.owner_signature, ta.owner_signed_at,
        ta.tenant_signature, ta.tenant_signed_at,
        ta.owner_bank_name, ta.owner_account_number, ta.owner_account_name
      FROM payments p
      LEFT JOIN tenancies t ON t.ref = 'TEN-FROM-' || p.ref
      LEFT JOIN tenancy_agreements ta ON ta.tenancy_id = t.id
      ORDER BY p.created_at DESC
    `);
    json(res, 200, { success: true, payments: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// A distinct, trackable "handover happened" step — previously the only
// signal was payment status flipping to 'confirmed', with no way to tell
// whether the physical/practical handover itself had actually occurred.
// Deliberately doesn't require the agreement to be signed first (admin
// keeps the judgment call — this just records the fact and notifies both
// sides), matching how release itself isn't hard-blocked either.
async function handleConfirmHandover(req, res, ref) {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  try {
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS handover_confirmed_at TIMESTAMPTZ`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS handover_confirmed_by TEXT`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS buyer_email TEXT DEFAULT ''`).catch(() => {});
    const r = await db.query(
      `UPDATE payments SET handover_confirmed_at=NOW(), handover_confirmed_by=$1 WHERE ref=$2 RETURNING *`,
      [admin.email || 'Admin', ref]
    );
    if (!r.rows.length) return json(res, 404, { error: 'Payment not found' });
    const p = r.rows[0];
    await logActivity('Handover confirmed for ' + p.prop + ' (' + ref + ') by ' + (admin.email || 'Admin'));

    const propOwnerId = p.property_id ? (await db.query('SELECT owner_id FROM properties WHERE id=$1', [p.property_id])).rows[0]?.owner_id : null;
    const buyerUserId = p.buyer_email ? (await db.query('SELECT id FROM registrations WHERE email=$1', [p.buyer_email])).rows[0]?.id : null;
    if (propOwnerId) createNotification(propOwnerId, 'handover_complete', '🤝 Handover Complete', p.prop + ' — the property has been handed over', { ref }).catch(() => {});
    if (buyerUserId) createNotification(buyerUserId, 'handover_complete', '🤝 Handover Complete', 'You now have access to ' + p.prop, { ref }).catch(() => {});

    json(res, 200, { success: true, payment: p });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleSavePayment(data, res) {
  const { ref, prop, buyer, phone, owner, ownerAcct, amount, fee, ownerAmt, status, notified, tenancy_id, release_note, property_id: propertyIdIn, unit_id: unitIdIn, unit_label, start, end } = data;
  if (!ref) return json(res, 400, { error: 'Payment ref required' });
  console.log('[save-payment] incoming ref=' + ref + ' status=' + status + ' property_id=' + propertyIdIn + ' unit_id=' + unitIdIn);
  try {
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS release_note TEXT DEFAULT ''`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS released_at TEXT`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS buyer_email TEXT DEFAULT ''`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS unit_id INTEGER`).catch(() => {});
    // Look up the row as it stands BEFORE this save so we only notify (and
    // auto-create a tenancy) on an actual status transition — e.g. editing
    // notes on an already-confirmed payment shouldn't re-fire either.
    const before = await db.query('SELECT status, property_id, buyer_email, unit_id FROM payments WHERE ref=$1', [ref]);
    const prevStatus = before.rows[0]?.status || null;
    const propertyId = propertyIdIn || before.rows[0]?.property_id || null;
    const buyerEmail = before.rows[0]?.buyer_email || '';
    const unitId = unitIdIn || before.rows[0]?.unit_id || null;

    await db.query(
      `INSERT INTO payments (ref,prop,buyer,phone,owner,owner_acct,amount,fee,owner_amt,status,notified,tenancy_id,release_note,unit_id,property_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
       ON CONFLICT (ref) DO UPDATE SET status=$10, notified=$11,
         confirmed_at=CASE WHEN $10='confirmed' THEN NOW()::text ELSE payments.confirmed_at END,
         release_note=CASE WHEN $13<>'' THEN $13 ELSE payments.release_note END,
         released_at=CASE WHEN $10='released' THEN NOW()::text ELSE payments.released_at END,
         unit_id=COALESCE($14, payments.unit_id), property_id=COALESCE($15, payments.property_id)`,
      [ref, prop||'', buyer||'', phone||'', owner||'', ownerAcct||'', amount||0, fee||0, ownerAmt||0, status||'pending', notified||'', tenancy_id||null, release_note||'', unitId, propertyId]
    );
    await logActivity('Payment ' + (status||'pending') + ': ' + ref);
    broadcast('payment_updated', { ref, status });

    // Fire owner/buyer emails on an actual transition into confirmed/released.
    // Never let a notification failure block the save itself.
    const isNewTransition = status && status !== prevStatus;
    console.log('[save-payment] ref=' + ref + ' prevStatus=' + prevStatus + ' newStatus=' + status + ' isNewTransition=' + isNewTransition + ' resolvedPropertyId=' + propertyId + ' resolvedUnitId=' + unitId);
    if (isNewTransition && (status === 'confirmed' || status === 'released')) {
      const p = { ref, prop, buyer, owner, amount, fee, owner_amt: ownerAmt };
      const ownerEmail = await getPropertyOwnerEmail(propertyId);
      const propOwnerId = propertyId ? (await db.query('SELECT owner_id FROM properties WHERE id=$1', [propertyId])).rows[0]?.owner_id : null;
      const buyerUserId = buyerEmail ? (await db.query('SELECT id FROM registrations WHERE email=$1', [buyerEmail])).rows[0]?.id : null;
      if (status === 'confirmed') {
        if (ownerEmail) sendEmail(ownerEmail, '✅ Payment Confirmed — ' + prop, paymentConfirmedEmail(p, true)).catch(e => console.warn('Owner confirm email failed:', e.message));
        if (buyerEmail) sendEmail(buyerEmail, '✅ Your Payment Has Been Confirmed', paymentConfirmedEmail(p, false)).catch(e => console.warn('Buyer confirm email failed:', e.message));
        if (propOwnerId) createNotification(propOwnerId, 'payment_confirmed', '✅ Payment Confirmed', prop + ' — handover can proceed', { ref }).catch(()=>{});
        if (buyerUserId) createNotification(buyerUserId, 'payment_confirmed', '✅ Payment Confirmed', 'Your payment for ' + prop + ' has been confirmed', { ref }).catch(()=>{});
      } else if (status === 'released') {
        if (ownerEmail) sendEmail(ownerEmail, '💸 Funds Released — ' + prop, paymentReleasedEmail(p)).catch(e => console.warn('Owner release email failed:', e.message));
        if (propOwnerId) createNotification(propOwnerId, 'payment_released', '💸 Funds Released', 'Your payout for ' + prop + ' has been sent', { ref }).catch(()=>{});
      }
    }

    // Keep a linked shortlet booking (if any) in sync with the payment: a
    // confirmed/released payment locks those dates in for real; a disputed
    // or reverted-to-pending payment frees them back up for other guests.
    if (isNewTransition) {
      await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS ref TEXT`).catch(() => {});
      if (status === 'confirmed' || status === 'released') {
        await db.query(`UPDATE bookings SET status='confirmed' WHERE ref=$1`, [ref]).catch(() => {});
      } else if (status === 'disputed') {
        await db.query(`UPDATE bookings SET status='cancelled' WHERE ref=$1`, [ref]).catch(() => {});
      }
    }

    // Auto-create a Tenancy Tracker record the moment a rent/lease payment
    // is confirmed — previously this required a fully separate manual
    // "Add Tenancy" entry, duplicating data already on the payment itself.
    // Also handles auto-delisting the property from public/live listing
    // once it's no longer available — see maybeDelistProperty() above for
    // why that's multi-unit-aware rather than an unconditional flip.
    if (isNewTransition && status === 'confirmed' && propertyId) {
      try {
        const propR = await db.query(
          "SELECT title, owner, COALESCE(listing_type,type,'rent') as listing_type, COALESCE(lease_duration_years::text,'1') as lease_duration_years, COALESCE(rent_category,'standard') as rent_category FROM properties WHERE id=$1",
          [propertyId]
        );
        const propRow = propR.rows[0];
        console.log('[save-payment] tenancy check ref=' + ref + ' propertyRow=' + JSON.stringify(propRow));
        // Shortlets are meant to be booked repeatedly — a single confirmed
        // booking must never create a long-running tenancy or delist the
        // property. That's handled entirely by the separate bookings-table
        // sync above instead.
        const isShortlet = propRow && propRow.listing_type === 'rent' && propRow.rent_category === 'shortlet';
        if (propRow && !isShortlet && (propRow.listing_type === 'rent' || propRow.listing_type === 'lease')) {
          const startDate = start || new Date().toISOString().slice(0, 10);
          const years = propRow.listing_type === 'lease' ? (Number(propRow.lease_duration_years) || 1) : 1;
          const endDate = end || new Date(new Date(startDate).setFullYear(new Date(startDate).getFullYear() + years)).toISOString().slice(0, 10);
          await createTenancyRecord({
            ref: 'TEN-FROM-' + ref,
            type: propRow.listing_type,
            property: unit_label ? propRow.title + ' — ' + unit_label : (prop || propRow.title),
            property_id: propertyId, unit_id: unitId,
            // Falls back to a clear placeholder rather than throwing — a
            // payment can legitimately have no buyer name (e.g. a manual
            // test entry added directly in admin without one), and a
            // tenancy record the admin can rename later is far more useful
            // than silently having none created at all.
            tenant: buyer || 'Tenant (name not provided — update manually)',
            phone: phone || '', owner: owner || propRow.owner || '',
            amount: amount || 0, start: startDate, end: endDate,
            notes: 'Auto-created from confirmed payment ' + ref
          });
          console.log('[save-payment] tenancy auto-created for ref=' + ref + ' as TEN-FROM-' + ref);
          await maybeDelistProperty(propertyId, propRow.listing_type);
        } else if (propRow && propRow.listing_type === 'buy') {
          // Buy has no ongoing occupancy to track (no tenancy), but a sold
          // unit still needs marking so it stops showing as vacant, and the
          // whole property still needs the same all-units-taken check
          // before coming down from public listing.
          if (unitId) {
            await db.query("UPDATE property_units SET status='occupied' WHERE id=$1", [unitId]);
          }
          await maybeDelistProperty(propertyId, propRow.listing_type);
          console.log('[save-payment] buy sale processed for ref=' + ref + ' — unit/property availability updated');
        } else {
          console.log('[save-payment] tenancy/delist SKIPPED for ref=' + ref + ' — property not found, listing_type unrecognized, or shortlet (rent_category=' + (propRow ? propRow.rent_category : 'n/a') + ')');
        }
      } catch (te) {
        // Never let tenancy auto-creation break the payment confirmation
        // itself — the payment is already saved successfully by this point.
        console.error('Auto tenancy creation failed for payment ' + ref + ':', te.message);
      }
    } else if (status === 'confirmed') {
      console.log('[save-payment] tenancy auto-create NOT ATTEMPTED for ref=' + ref + ' — isNewTransition=' + isNewTransition + ' propertyId=' + propertyId + ' (need isNewTransition=true AND a resolvable property_id)');
    }

    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── Shortlet booking / availability ──────────────────────────────────────────
async function ensureBookingsTable() {
  await db.query(`CREATE TABLE IF NOT EXISTS bookings (
    id SERIAL PRIMARY KEY,
    property_id TEXT NOT NULL,
    ref TEXT,
    check_in DATE NOT NULL,
    check_out DATE NOT NULL,
    guest_name TEXT DEFAULT '',
    guest_email TEXT DEFAULT '',
    guest_phone TEXT DEFAULT '',
    nights INTEGER DEFAULT 0,
    amount NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`).catch(() => {});
}

async function handleGetAvailability(propertyId, res) {
  try {
    await ensureBookingsTable();
    // Confirmed bookings always block their dates. Pending ones (payment
    // submitted, not yet admin-confirmed) only block for 48h -- past that,
    // treat the hold as abandoned so an unconfirmed transfer can't
    // permanently lock a guest out of those dates.
    const r = await db.query(
      `SELECT check_in, check_out FROM bookings
       WHERE property_id=$1 AND status<>'cancelled'
         AND (status='confirmed' OR created_at > NOW() - INTERVAL '48 hours')`,
      [propertyId]
    );
    const fmt = d => (d instanceof Date) ? d.toISOString().slice(0,10) : String(d).slice(0,10);
    json(res, 200, { success: true, booked: r.rows.map(row => ({ check_in: fmt(row.check_in), check_out: fmt(row.check_out) })) });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Returns null if the range is free, or an error string if it overlaps an
// existing (non-cancelled, non-stale-pending) booking.
async function checkBookingConflict(propertyId, checkIn, checkOut) {
  await ensureBookingsTable();
  const r = await db.query(
    `SELECT 1 FROM bookings
     WHERE property_id=$1 AND status<>'cancelled'
       AND (status='confirmed' OR created_at > NOW() - INTERVAL '48 hours')
       AND check_in < $3 AND check_out > $2
     LIMIT 1`,
    [propertyId, checkIn, checkOut]
  );
  return r.rows.length ? 'Those dates are no longer available — please pick different dates.' : null;
}

async function handleSubmitPayment(data, res) {
  // Public endpoint: a buyer/renter just clicked "I've Made the Transfer" on the
  // website or mobile app. This was previously only reachable via the
  // admin-authenticated /admin/save-payment route, so customer submissions from
  // the payment modal were silently dropped (the frontend fetch 404'd and was
  // swallowed by .catch(()=>{})) and never appeared in the admin payments queue.
  const {
    ref, property_id, property_title, buyer_name, buyer_email, buyer_phone,
    owner, amount, unit_id, unit_label, unit_price, prop, buyer, phone, receipt_url,
    check_in, check_out
  } = data;
  if (!ref) return json(res, 400, { error: 'Payment ref required' });
  if (!receipt_url) return json(res, 400, { error: 'Transfer receipt is required' });

  let rawAmount = Number(unit_price || amount || 0) || 0;
  let nights = 0;

  // Shortlet booking: dates were sent, so compute the authoritative amount
  // server-side from the property's real nightly_rate (never trust a
  // client-computed total) and reject if those dates just got taken.
  if (check_in && check_out) {
    if (!property_id) return json(res, 400, { error: 'property_id required for a dated booking' });
    const ci = new Date(check_in), co = new Date(check_out);
    if (isNaN(ci) || isNaN(co) || co <= ci) return json(res, 400, { error: 'Invalid check-in/check-out dates' });
    nights = Math.round((co - ci) / 86400000);
    try {
      const propR = await db.query('SELECT nightly_rate FROM properties WHERE id=$1', [property_id]);
      const nightlyRate = Number(propR.rows[0]?.nightly_rate || 0);
      if (!nightlyRate) return json(res, 400, { error: 'This property has no nightly rate set' });
      rawAmount = nightlyRate * nights;
      const conflict = await checkBookingConflict(property_id, check_in, check_out);
      if (conflict) return json(res, 409, { error: conflict });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  const fee = Math.round(rawAmount * 0.10);
  const ownerAmt = rawAmount - fee;
  const propLabel = prop || (unit_label ? property_title + ' — ' + unit_label : property_title) || '';
  try {
    // Defensive: this is now a public write path (previously only reachable via
    // admin auth), so make sure the table exists rather than assuming it does.
    await db.query(`CREATE TABLE IF NOT EXISTS payments (
      ref TEXT PRIMARY KEY, prop TEXT DEFAULT '', buyer TEXT DEFAULT '',
      phone TEXT DEFAULT '', owner TEXT DEFAULT '', owner_acct TEXT DEFAULT '',
      amount NUMERIC DEFAULT 0, fee NUMERIC DEFAULT 0, owner_amt NUMERIC DEFAULT 0,
      status TEXT DEFAULT 'pending', notified TEXT DEFAULT '', tenancy_id TEXT,
      confirmed_at TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS receipt_url TEXT DEFAULT ''`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS property_id TEXT`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS release_note TEXT DEFAULT ''`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS released_at TEXT`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS buyer_email TEXT DEFAULT ''`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS unit_id INTEGER`).catch(() => {});
    await db.query(
      `INSERT INTO payments (ref,prop,buyer,phone,owner,owner_acct,amount,fee,owner_amt,status,notified,tenancy_id,receipt_url,property_id,buyer_email,unit_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending_confirmation','',NULL,$10,$11,$12,$13)
       ON CONFLICT (ref) DO NOTHING`,
      [ref, propLabel, buyer || buyer_name || '', phone || buyer_phone || '', owner || '', '', rawAmount, fee, ownerAmt, receipt_url, property_id || null, buyer_email || '', unit_id || null]
    );
    await logActivity('Payment submitted by customer: ' + ref + (property_id ? ' (property ' + property_id + ')' : ''));
    broadcast('payment_updated', { ref, status: 'pending_confirmation' });

    if (check_in && check_out && nights > 0) {
      await ensureBookingsTable();
      const bookingR = await db.query(
        `INSERT INTO bookings (property_id, ref, check_in, check_out, guest_name, guest_email, guest_phone, nights, amount, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending') RETURNING id`,
        [property_id, ref, check_in, check_out, buyer || buyer_name || '', buyer_email || '', phone || buyer_phone || '', nights, rawAmount]
      );
      // Narrow (not eliminate) the check-then-insert race: re-verify no other
      // booking for these dates snuck in between the earlier check and this
      // insert. A true guarantee needs a DB-level exclusion constraint; this
      // is a reasonable mitigation for a manually-reviewed booking flow.
      const dupe = await db.query(
        `SELECT 1 FROM bookings
         WHERE property_id=$1 AND id<>$2 AND status<>'cancelled'
           AND (status='confirmed' OR created_at > NOW() - INTERVAL '48 hours')
           AND check_in < $4 AND check_out > $3 LIMIT 1`,
        [property_id, bookingR.rows[0].id, check_in, check_out]
      );
      if (dupe.rows.length) {
        await db.query(`UPDATE bookings SET status='cancelled' WHERE id=$1`, [bookingR.rows[0].id]);
        await db.query(`UPDATE payments SET status='cancelled' WHERE ref=$1`, [ref]);
        return json(res, 409, { error: 'Those dates were just booked by someone else — please pick different dates.' });
      }
    }

    json(res, 200, { success: true, ref, amount: rawAmount, nights: nights || undefined });
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

// ── Partner Login — POST /partner/login ──────────────────────────────────────
// Checks {name, token} against the PARTNERS_JSON directory. On success, issues
// the same owner:<id>:<timestamp> token format the /owner/* endpoints already
// understand, but with a stable per-partner pseudo-id (PARTNER-<slug>) instead
// of a real registrations.id — so a partner's properties (owner_id = that
// pseudo-id) can never collide with, or be confused for, a real owner's.
async function handlePartnerLogin(data, res) {
  const { name, token } = data;
  if (!name || !token) return json(res, 400, { error: 'Name and access token are required.' });
  const partner = PARTNERS.find(p => p.name === name);
  if (!partner || partner.token !== token) {
    return json(res, 401, { error: 'Invalid name or access token.' });
  }
  const partnerId = partnerSlug(name);
  const [fname, ...rest] = name.trim().split(/\s+/);
  const lname = rest.join(' ') || fname;

  // Make sure a lightweight, pre-approved registrations row exists for this
  // partner — /owner/* endpoints (verification guard, profile, etc.) look
  // the id up there. Pre-verified since partners are vetted out-of-band.
  try {
    await db.query(
      `INSERT INTO registrations (id, fname, lname, email, role, type, status, is_verified, initials)
       VALUES ($1,$2,$3,$4,'owner','partner','approved',true,$5)
       ON CONFLICT (id) DO NOTHING`,
      [partnerId, fname, lname, partnerId.toLowerCase() + '@partners.geoestate.local',
       (fname[0] || 'P').toUpperCase() + (lname[0] || '').toUpperCase()]
    );
  } catch(e) { console.warn('Partner registrations row ensure failed:', e.message); }

  const ownerToken = 'owner:' + partnerId + ':' + Date.now();
  json(res, 200, {
    success: true,
    token: ownerToken,
    owner: { id: partnerId, fname, lname, role: 'partner' }
  });
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
    if (!r.rows.length) {
      // This is the real bug behind "I uploaded my documents and they're
      // definitely somewhere, but admin shows nothing": ownerId (from the
      // session token) didn't match any registrations row at all -- a stale
      // token, or verifying moments after signup before the row had fully
      // committed. The selfie/ID files themselves upload fine (they go
      // straight to Supabase Storage, unrelated to this row), so from the
      // user's side it looks like "my documents are already saved" -- but
      // nothing ever linked those file URLs back to their registration,
      // because there was no registration row to update. Previously this
      // silently returned success from the block below (an UPDATE matching
      // zero rows isn't a SQL error), so the person genuinely believed it
      // worked. Fail loudly now so the frontend can tell them to re-login.
      return json(res, 404, { error: 'We could not find your account — please sign out and log back in, then try again.' });
    }
    if (r.rows[0]?.is_verified) return json(res, 200, { success: true, alreadyVerified: true, message: 'Already verified — no action needed.' });

    const { nin, doc_type, doc_url, selfie_url, other_doc_url, dob, gender, occupation, employer, state, lga, address, next_of_kin, next_of_kin_rel, next_of_kin_phone } = data;
    // Try full update with all fields, fall back to minimal if columns missing
    let updateResult;
    try {
      updateResult = await db.query(
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
          photo_url=COALESCE(NULLIF($15,''),photo_url),
          id_doc_url=COALESCE(NULLIF($16,''),id_doc_url),
          other_doc_url=COALESCE(NULLIF($17,''),other_doc_url),
          updated_at=NOW()
        WHERE id=$4`,
        [nin||'', doc_type + '|' + (doc_url||''), 'review', ownerId,
         dob||'', gender||'', occupation||'', employer||'',
         state||'', lga||'', address||'',
         next_of_kin||'', next_of_kin_rel||'', next_of_kin_phone||'',
         selfie_url||'', doc_url||'', other_doc_url||'']
      );
    } catch(e) {
      // Fallback: minimal update if extended columns don't exist
      updateResult = await db.query(
        'UPDATE registrations SET nin=$1, doc=$2, is_verified=false, status=$3, photo_url=COALESCE(NULLIF($5,\'\'),photo_url), id_doc_url=COALESCE(NULLIF($6,\'\'),id_doc_url), updated_at=NOW() WHERE id=$4',
        [nin||'', doc_type + '|' + (doc_url||''), 'review', ownerId, selfie_url||'', doc_url||'']
      );
    }
    // Same guard as above, after the actual save attempt: if this matched
    // zero rows, nothing was persisted -- don't report success.
    if (!updateResult || updateResult.rowCount === 0) {
      return json(res, 404, { error: 'We could not save your verification — please sign out and log back in, then try again.' });
    }
    await logActivity('Owner identity submitted for review: ' + ownerId);
    json(res, 200, { success: true, message: 'Identity submitted. You will be notified once verified (usually within 24 hours).' });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Per-property analytics for the owner dashboard: view count (see
// handleRecordPropertyView above), enquiry count, and a simple
// enquiry-rate percentage. One row per property, most-viewed first.
async function handleOwnerAnalytics(ownerId, res) {
  try {
    await db.query(`ALTER TABLE properties ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0`).catch(() => {});
    const r = await db.query(`
      SELECT p.id, p.title, p.status, COALESCE(p.listing_type, p.type, 'rent') as listing_type,
        p.img, p.created_at, COALESCE(p.view_count, 0) as view_count,
        (SELECT COUNT(*)::int FROM enquiries e WHERE e.property_id = p.id) as enquiry_count
      FROM properties p
      WHERE p.owner_id = $1
      ORDER BY COALESCE(p.view_count, 0) DESC, p.created_at DESC
    `, [ownerId]);
    const rows = r.rows.map(row => ({
      ...row,
      enquiry_rate: row.view_count > 0 ? Math.round((row.enquiry_count / row.view_count) * 100) : 0,
      days_live: Math.max(0, Math.floor((Date.now() - new Date(row.created_at).getTime()) / (1000 * 60 * 60 * 24)))
    }));
    const totals = {
      total_views: rows.reduce((s, r) => s + r.view_count, 0),
      total_enquiries: rows.reduce((s, r) => s + r.enquiry_count, 0),
      total_properties: rows.length
    };
    json(res, 200, { success: true, properties: rows, totals });
  } catch (e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerProperties(ownerId, urlFull, res) {
  try {
    const params = new URL('http://x' + urlFull).searchParams;
    const type = params.get('type');
    let q = "SELECT id,title,owner,owner_id,type,COALESCE(listing_type,type,'rent') as listing_type,status,price,COALESCE(monthly_rent,NULL) as monthly_rent,COALESCE(annual_rent,NULL) as annual_rent,COALESCE(nightly_rate,NULL) as nightly_rate,COALESCE(sale_price,NULL) as sale_price,COALESCE(lease_price,NULL) as lease_price,state,lga,address,img,COALESCE(images,'[]'::jsonb) as images,video_url,COALESCE(docs,'[]'::jsonb) as docs,COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,COALESCE(description,'') as description,COALESCE(amenities,'[]'::jsonb) as amenities,notes,created_at FROM properties WHERE owner_id=$1";
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
  // ── Verification guard ──────────────────────────────────────
  let vrRow;
  try {
    const vr = await db.query('SELECT is_verified, status FROM registrations WHERE id=$1', [ownerId]);
    if (!vr.rows.length) return json(res, 404, { error: 'Owner not found' });
    vrRow = vr.rows[0];
  } catch(e) {
    const vr2 = await db.query('SELECT status FROM registrations WHERE id=$1', [ownerId]);
    if (!vr2.rows.length) return json(res, 404, { error: 'Owner not found' });
    vrRow = { is_verified: vr2.rows[0].status === 'approved', status: vr2.rows[0].status };
  }
  if (!vrRow.is_verified && vrRow.status !== 'approved') return json(res, 403, {
    error: 'Identity not yet verified',
    needsVerification: true,
    message: 'Please complete identity verification to list properties. You only need to do this once.'
  });

  // ── Core field validation ───────────────────────────────────
  const { title, listing_type } = data;
  if (!title) return json(res, 400, { error: 'Property title required' });
  if (!listing_type || !['rent','buy','lease'].includes(listing_type)) {
    return json(res, 400, { error: 'listing_type must be rent, buy, or lease' });
  }

  // ── Shared fields ───────────────────────────────────────────
  const propId = 'PROP-' + Date.now();
  const {
    price, state, lga, address, landmark,
    img, images, video_url, docs, bedrooms, bathrooms, toilets,
    size_sqm, year_built, description, amenities,
    furnishing, notes, property_type, lat, lng, units
  } = data;

  // ── property_type check-constraint mapping ──────────────────
  // The DB only allows property_type to be one of:
  //   single | multi_unit | hotel | commercial
  // but the listing forms send much more specific values
  // (flat, house, bungalow, shortlet-villa, office, land, etc).
  // Map to the closest allowed bucket for the constrained column,
  // and keep the original specific value in metadata so it isn't lost
  // for display/search purposes.
  const PROPERTY_TYPE_MAP = {
    // rent form
    flat: 'single', house: 'single', room: 'single', bungalow: 'single',
    'shortlet-apartment': 'hotel', 'shortlet-studio': 'hotel', 'shortlet-villa': 'hotel',
    office: 'commercial', shop: 'commercial', warehouse: 'commercial', land: 'single',
    // buy form (additional values)
    terraced: 'single', detached: 'single', 'semi-detached': 'single', mansion: 'single',
    estate: 'multi_unit',
    // lease form (additional values)
    factory: 'commercial', plaza: 'commercial', residential: 'single', 'mixed-use': 'commercial'
  };
  const property_subtype = property_type || null;
  const property_type_bucket = PROPERTY_TYPE_MAP[property_type] || 'single';

  // ── Media validation: require a minimum number of photos ────
  const imageList = Array.isArray(images) ? images.filter(Boolean) : [];
  if (imageList.length < 3) {
    return json(res, 400, { error: 'Please upload at least 3 photos of the property.' });
  }
  const docList = Array.isArray(docs) ? docs.filter(Boolean) : [];

  // ── Type-specific fields ────────────────────────────────────
  let monthly_rent = null, annual_rent = null, sale_price = null, lease_price = null;
  let nightly_rate = null, rent_category = 'standard';
  let rent_frequency = null, advance_payment = null, caution_fee = null, agency_fee = null;
  let rent_includes = [], tenant_type = null, pets_allowed = null;
  let min_nights = null, max_nights = null, weekend_rate = null, cleaning_fee = null;
  let checkin_time = null, checkout_time = null, house_rules = null;
  let negotiable = null, tenure = null, floors = null, land_size_sqm = null;
  let doc_coo = null, doc_deed = null, doc_survey = null, doc_approval = null, sale_agreement = null;
  let lease_type = null, lease_payment_freq = null, lease_duration_years = null;
  let lease_start_date = null, renewal_option = null, escalation_pct = null;
  let permitted_use = null, prop_condition = null, parking_spaces = null, lease_agreement_doc = null;
  let agreement_doc = null;

  // ── Metadata JSONB: holds ALL type-specific extras ──────────
  const metadata = { property_subtype };

  if (listing_type === 'rent') {
    rent_category  = data.rent_category || 'standard';
    caution_fee    = data.caution_fee    || null;
    rent_includes  = Array.isArray(data.rent_includes) ? data.rent_includes : [];
    agreement_doc  = data.agreement_doc  || null;

    if (rent_category === 'shortlet') {
      nightly_rate   = data.nightly_rate   || null;
      monthly_rent   = nightly_rate ? nightly_rate * 30 : null; // DB compat
      min_nights     = data.min_nights     || 1;
      max_nights     = data.max_nights     || null;
      weekend_rate   = data.weekend_rate   || null;
      cleaning_fee   = data.cleaning_fee   || null;
      checkin_time   = data.checkin_time   || '14:00';
      checkout_time  = data.checkout_time  || '11:00';
      house_rules    = data.house_rules    || null;
      Object.assign(metadata, { nightly_rate, min_nights, max_nights, weekend_rate, cleaning_fee, checkin_time, checkout_time, house_rules });
    } else {
      // Standard tenancy
      annual_rent    = data.annual_rent    || null;
      monthly_rent   = annual_rent ? Math.round(annual_rent / 12) : (data.monthly_rent || null);
      rent_frequency = data.rent_frequency || 'annual';
      advance_payment= data.advance_payment|| null;
      agency_fee     = data.agency_fee     || null;
      tenant_type    = data.tenant_type    || null;
      pets_allowed   = data.pets_allowed   || null;
      Object.assign(metadata, { annual_rent, rent_frequency, advance_payment, agency_fee, tenant_type, pets_allowed });
    }
    metadata.rent_category = rent_category;
    metadata.rent_includes = rent_includes;
    metadata.caution_fee   = caution_fee;
    metadata.agreement_doc = agreement_doc;

  } else if (listing_type === 'buy') {
    sale_price     = data.sale_price     || null;
    negotiable     = data.negotiable     || null;
    tenure         = data.tenure         || null;
    floors         = data.floors         || null;
    land_size_sqm  = data.land_size_sqm  || null;
    doc_coo        = data.doc_coo        || null;
    doc_deed       = data.doc_deed       || null;
    doc_survey     = data.doc_survey     || null;
    doc_approval   = data.doc_approval   || null;
    sale_agreement = data.sale_agreement || null;
    Object.assign(metadata, { negotiable, tenure, floors, land_size_sqm, doc_coo, doc_deed, doc_survey, doc_approval, sale_agreement });

  } else if (listing_type === 'lease') {
    lease_price          = data.lease_price          || null;
    lease_type           = data.lease_type           || null;
    lease_payment_freq   = data.lease_payment_freq   || null;
    lease_duration_years = data.lease_duration_years || null;
    lease_start_date     = data.lease_start_date     || null;
    renewal_option       = data.renewal_option       || null;
    escalation_pct       = data.escalation_pct       || null;
    permitted_use        = data.permitted_use        || null;
    prop_condition       = data.condition            || null;
    parking_spaces       = data.parking_spaces       || null;
    floors               = data.floors               || null;
    land_size_sqm        = data.land_size_sqm        || null;
    lease_agreement_doc  = data.lease_agreement      || null;
    doc_coo              = data.doc_coo              || null;
    doc_survey           = data.doc_survey           || null;
    Object.assign(metadata, {
      lease_type, lease_payment_freq, lease_duration_years,
      lease_start_date, renewal_option, escalation_pct,
      permitted_use, condition: prop_condition,
      parking_spaces, doc_coo, doc_survey, lease_agreement: lease_agreement_doc
    });
  }

  // Build display price string
  const displayPrice = price ||
    (listing_type === 'rent' && rent_category === 'shortlet' ? '₦' + (nightly_rate||0).toLocaleString() + '/night'
    : listing_type === 'rent'  ? '₦' + (annual_rent||monthly_rent||0).toLocaleString() + '/yr'
    : listing_type === 'buy'   ? '₦' + (sale_price||0).toLocaleString()
    : listing_type === 'lease' ? '₦' + (lease_price||0).toLocaleString() + '/yr'
    : '');

  try {
    await db.query(
      `INSERT INTO properties (
         id, title, owner_id, owner, listing_type, type, status, price,
         property_type, state, lga, address, landmark,
         img, images, bedrooms, bathrooms, toilets, size_sqm, land_size_sqm, year_built, floors, parking_spaces,
         description, amenities, furnishing, notes, submitted,
         monthly_rent, annual_rent, sale_price, lease_price, nightly_rate,
         rent_category, rent_frequency, advance_payment, caution_fee, agency_fee,
         rent_includes, tenant_type, pets_allowed,
         min_nights, max_nights, weekend_rate, cleaning_fee,
         checkin_time, checkout_time, house_rules, agreement_doc,
         negotiable, tenure,
         doc_coo, doc_deed, doc_survey, doc_approval, sale_agreement,
         lease_type, lease_payment_freq, lease_duration_years,
         lease_start_date, renewal_option, escalation_pct, permitted_use, condition,
         lat, lng, geo, metadata, video_url, docs
       )
       VALUES (
         $1, $2, $3, (SELECT fname||' '||lname FROM registrations WHERE id=$3), $4, $4,
         'pending', $5,
         $6, $7, $8, $9, $10,
         $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
         $21, $22, $23, $24, $25,
         $26, $27, $28, $29, $30,
         $31, $32, $33, $34, $35,
         $36, $37, $38,
         $39, $40, $41, $42,
         $43, $44, $45, $46,
         $47, $48,
         $49, $50, $51, $52, $53,
         $54, $55, $56,
         $57, $58, $59, $60, $61,
         $62, $63, $64,
         $65, $66, $67
       )`,
      [
        propId, title, ownerId, listing_type, displayPrice,
        property_type_bucket||null, state||'', lga||'', address||'', landmark||'',
        img||imageList[0]||'', JSON.stringify(imageList), bedrooms||null, bathrooms||null, toilets||null,
        size_sqm||null, land_size_sqm||null, year_built||null, floors||null, parking_spaces||null,
        description||'', JSON.stringify(amenities||[]), furnishing||null, notes||'',
        new Date().toLocaleString('en-NG'),
        monthly_rent, annual_rent, sale_price, lease_price, nightly_rate,
        rent_category, rent_frequency, advance_payment, caution_fee, agency_fee,
        JSON.stringify(rent_includes), tenant_type, pets_allowed,
        min_nights, max_nights||null, weekend_rate, cleaning_fee,
        checkin_time, checkout_time, house_rules, agreement_doc,
        negotiable, tenure,
        doc_coo, doc_deed, doc_survey, doc_approval, sale_agreement,
        lease_type, lease_payment_freq, lease_duration_years,
        lease_start_date||null, renewal_option, escalation_pct, permitted_use, prop_condition,
        lat||null, lng||null,
        !!(lat||null) && !!(lng||null),
        JSON.stringify(metadata),
        video_url || null,
        JSON.stringify(docList)
      ]
    );

    // ── Individual units (optional) ─────────────────────────────
    // Lets an owner define each separately-rented room/flat/unit right at
    // listing time (label, price, own photos, description) instead of only
    // being able to add them one-by-one afterward via "Manage Units". Units
    // can still be added/edited/removed later through that same screen —
    // this just seeds it up front when the owner already knows the breakdown.
    const unitList = Array.isArray(units) ? units.filter(u => u && u.unit_label) : [];
    if (unitList.length) {
      try {
        await db.query(`ALTER TABLE property_units ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]'`).catch(() => {});
        await db.query(`ALTER TABLE property_units ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`).catch(() => {});
        for (const u of unitList) {
          await db.query(
            'INSERT INTO property_units (property_id,unit_label,unit_type,floor_level,capacity,monthly_price,notes,images,description) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
            [
              propId, u.unit_label, u.unit_type || 'room', u.floor_level || '', u.capacity || 1,
              u.monthly_price || u.price || null, u.notes || '',
              JSON.stringify(Array.isArray(u.images) ? u.images : []), u.description || ''
            ]
          );
        }
      } catch (ue) {
        // Don't fail the whole listing submission just because unit seeding
        // hit an issue — the property itself is already saved successfully.
        console.error('Unit seeding failed for ' + propId + ':', ue.message);
      }
    }

    await logActivity('Owner ' + ownerId + ' listed new ' + listing_type + ' property: ' + title);
    json(res, 200, {
      success: true,
      propertyId: propId,
      message: 'Property submitted for review. It will go live once approved.'
    });
  } catch(e) {
    console.error('handleOwnerAddProperty error:', e.message);
    json(res, 500, { error: e.message });
  }
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
      images JSONB DEFAULT '[]', description TEXT DEFAULT '',
      notes TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(()=>{});
    // Table may already exist from before images/description were added
    await db.query(`ALTER TABLE property_units ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]'`).catch(()=>{});
    await db.query(`ALTER TABLE property_units ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`).catch(()=>{});
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
  const { unit_label, unit_type, floor_level, capacity, monthly_price, notes, images, description } = data;
  if (!unit_label) return json(res, 400, { error: 'unit_label required' });
  try {
    const r = await db.query(
      'INSERT INTO property_units (property_id,unit_label,unit_type,floor_level,capacity,monthly_price,notes,images,description) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [propId, unit_label, unit_type||'room', floor_level||'', capacity||1, monthly_price||null, notes||'', JSON.stringify(Array.isArray(images)?images:[]), description||'']
    );
    await logActivity('Unit added: ' + unit_label + ' to property ' + propId);
    json(res, 200, { success: true, unit: r.rows[0] });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// Bulk-imports many units at once from a parsed CSV (parsing itself happens
// client-side — this just accepts an already-parsed array of row objects,
// same shape as a single handleAddUnit call). Photos aren't practical via
// CSV (no way to embed image files in text), so bulk-imported units start
// with no photo — the owner can add one per unit afterward the same way
// they would for any manually-added unit.
async function handleBulkAddUnits(ownerId, propId, data, res) {
  if (ownerId) {
    const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
    if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  }
  const rows = Array.isArray(data.units) ? data.units : [];
  if (!rows.length) return json(res, 400, { error: 'No units provided' });
  if (rows.length > 500) return json(res, 400, { error: 'Too many rows in one import (max 500) — split into smaller batches' });
  const inserted = [];
  const skipped = [];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i] || {};
    const unit_label = (row.unit_label || '').toString().trim();
    if (!unit_label) { skipped.push({ row: i + 1, reason: 'Missing unit_label' }); continue; }
    try {
      const capacity = parseInt(row.capacity, 10);
      const monthly_price = parseFloat(row.monthly_price);
      const r = await db.query(
        'INSERT INTO property_units (property_id,unit_label,unit_type,floor_level,capacity,monthly_price,notes,description) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,unit_label',
        [propId, unit_label, (row.unit_type||'room').toString().trim() || 'room', (row.floor_level||'').toString().trim(),
         Number.isFinite(capacity) && capacity > 0 ? capacity : 1,
         Number.isFinite(monthly_price) && monthly_price > 0 ? monthly_price : null,
         (row.notes||'').toString().trim(), (row.description||'').toString().trim()]
      );
      inserted.push(r.rows[0]);
    } catch (e) {
      skipped.push({ row: i + 1, reason: e.message });
    }
  }
  await logActivity('Bulk-imported ' + inserted.length + ' unit(s) to property ' + propId + (skipped.length ? ' (' + skipped.length + ' skipped)' : ''));
  json(res, 200, { success: true, inserted: inserted.length, skipped });
}

async function handleUpdateUnit(ownerId, propId, unitId, data, res) {
  if (ownerId) {
    const own = await db.query('SELECT id FROM properties WHERE id=$1 AND owner_id=$2', [propId, ownerId]);
    if (!own.rows.length) return json(res, 403, { error: 'Property not found or not yours' });
  }
  try {
    const allowed = ['unit_label','unit_type','floor_level','capacity','monthly_price','status','current_tenant_id','occupied_since','lease_end','notes','images','description'];
    const fields = Object.entries(data).filter(([k]) => allowed.includes(k));
    if (!fields.length) return json(res, 400, { error: 'No valid fields' });
    const sets = fields.map(([k],i) => k === 'images' ? `${k}=$${i+2}::jsonb` : `${k}=$${i+2}`).join(',');
    const r = await db.query(`UPDATE property_units SET ${sets},updated_at=NOW() WHERE id=$1 AND property_id=$${fields.length+2} RETURNING *`,
      [unitId, ...fields.map(([k,v])=> k === 'images' ? JSON.stringify(Array.isArray(v)?v:[]) : v), propId]);
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
      images JSONB DEFAULT '[]', description TEXT DEFAULT '',
      notes TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(()=>{});
    // Table may already exist from before images/description were added
    await db.query(`ALTER TABLE property_units ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]'`).catch(()=>{});
    await db.query(`ALTER TABLE property_units ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`).catch(()=>{});
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
    if (url.match(/^\/properties\/([^/]+)\/availability$/)) return handleGetAvailability(url.split('/')[2], res);
    const ownerRatingsMatch = url.match(/^\/owner\/([^/]+)\/ratings$/);
    if (ownerRatingsMatch) return handleGetOwnerRatings(ownerRatingsMatch[1], res);
    if (url.match(/^\/properties\/([^/]+)$/)) return handlePublicPropertyById(url.split('/')[2], res);
    if (url === '/events')                   return handleSSE(req, res);
    if (url === '/support-staff-setup') {
      const token = new URL('http://x' + urlFull).searchParams.get('token');
      return handleGetStaffSetup(token, res);
    }

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
      if (url === '/admin/support-staff')    return handleListSupportStaff(res);
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
      if (url === '/owner/tenancies')        return handleOwnerTenancies(ownerId, res);
      if (url === '/owner/my-tenancies')     return handleMyTenancies(ownerId, res);
      if (url === '/owner/analytics')        return handleOwnerAnalytics(ownerId, res);
      const agreementGetMatch = url.match(/^\/owner\/tenancy\/(\d+)\/agreement$/);
      if (agreementGetMatch) return handleGetTenancyAgreement(ownerId, agreementGetMatch[1], res);
      if (url === '/owner/notifications')    return handleGetNotifications(ownerId, res);
      if (url === '/owner/favorites')        return handleGetFavorites(ownerId, res);
      if (url === '/owner/saved-searches')   return handleGetSavedSearches(ownerId, res);
      if (url === '/owner/conversations')    return handleGetConversations(ownerId, res);
      if (url === '/support/conversations') {
        if (ownerId !== SUPPORT_USER_ID) return json(res, 403, { error: 'Support staff only' });
        return handleGetSupportConversations(res);
      }
      if (url.startsWith('/owner/messages')) {
        const qp = new URL('http://x' + urlFull).searchParams;
        return handleGetThread(ownerId, qp.get('with'), qp.get('property_id'), res);
      }
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
      const staffMatch = url.match(/^\/admin\/support-staff\/(\d+)$/);
      if (staffMatch) return handleRevokeSupportStaff(staffMatch[1], res);
    }
    if (url.startsWith('/owner/')) {
      const ownerId = requireOwner(req, res);
      if (!ownerId) return;
      const owPropMatch = url.match(/^\/owner\/property\/([^/]+)$/);
      if (owPropMatch) return handleOwnerDeleteProperty(ownerId, owPropMatch[1], res);
      const owUnitMatch = url.match(/^\/owner\/property\/([^/]+)\/units\/(\d+)$/);
      if (owUnitMatch) return handleDeleteUnit(ownerId, owUnitMatch[1], owUnitMatch[2], res);
      const owFavMatch = url.match(/^\/owner\/favorites\/([^/]+)$/);
      if (owFavMatch) return handleRemoveFavorite(ownerId, owFavMatch[1], res);
      const owSearchMatch = url.match(/^\/owner\/saved-searches\/(\d+)$/);
      if (owSearchMatch) return handleRemoveSavedSearch(ownerId, owSearchMatch[1], res);
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
        if (url === '/admin/refresh')          return handleAdminRefresh(req, res);
        if (url === '/send-otp')             return handleSendOTP(data, res);
        if (url === '/verify-otp')           return handleVerifyOTP(data, res);
        if (url === '/register')             return handleRegister(data, res);
        if (url === '/user/login')            return handleUserLogin(data, res);
        if (url === '/enquiry')              return handleEnquiry(data, res);
        const viewMatch = url.match(/^\/properties\/([^/]+)\/view$/);
        if (viewMatch) return handleRecordPropertyView(viewMatch[1], res);
        if (url === '/submit-payment')       return handleSubmitPayment(data, res);
        if (url === '/upload-sign')           return handleSupabaseUploadSign(data, res);
        if (url === '/submit-dispute')       return handleSubmitDispute(data, res);
        if (url === '/geospatial-leads')     return handleGeospatialLead(data, res);

        // Owner auth (no token needed)
        if (url === '/owner/login')          return handleOwnerLogin(data, res);
        if (url === '/partner/login')        return handlePartnerLogin(data, res);
        if (url === '/support/login')        return handleSupportStaffLogin(data, res);

        // Owner routes (token required)
        if (url.startsWith('/owner/')) {
          const ownerId = requireOwner(req, res);
          if (!ownerId) return;
          if (url === '/owner/verify-identity') return handleOwnerVerifyIdentity(ownerId, data, res);
          if (url === '/owner/add-property')    return handleOwnerAddProperty(ownerId, data, res);
          if (url === '/owner/favorites')        return handleAddFavorite(ownerId, data, res);
          if (url === '/owner/saved-searches')   return handleAddSavedSearch(ownerId, data, res);
          if (url === '/owner/notifications/mark-read') return handleMarkNotificationsRead(ownerId, data, res);
          if (url === '/owner/ratings')          return handleAddRating(ownerId, data, res);
          if (url === '/owner/messages')         return handleSendMessage(ownerId, data, res, req);
          if (url === '/support/claim') {
            if (ownerId !== SUPPORT_USER_ID) return json(res, 403, { error: 'Support staff only' });
            return handleClaimConversation(req, data, res);
          }
          if (url === '/support/release') {
            if (ownerId !== SUPPORT_USER_ID) return json(res, 403, { error: 'Support staff only' });
            return handleReleaseConversation(req, data, res);
          }
          if (url === '/support/presence/ping') {
            if (ownerId !== SUPPORT_USER_ID) return json(res, 403, { error: 'Support staff only' });
            return handlePresencePing(req, data, res);
          }
          if (url === '/owner/push-token')       return handleRegisterPushToken(ownerId, data, res);
          const owPropMatch = url.match(/^\/owner\/property\/([^/]+)$/);
          if (owPropMatch) return handleOwnerUpdateProperty(ownerId, owPropMatch[1], data, res);
          const owUnitMatch = url.match(/^\/owner\/property\/([^/]+)\/units$/);
          if (owUnitMatch) return handleAddUnit(ownerId, owUnitMatch[1], data, res);
          const owUnitBulkMatch = url.match(/^\/owner\/property\/([^/]+)\/units\/bulk$/);
          if (owUnitBulkMatch) return handleBulkAddUnits(ownerId, owUnitBulkMatch[1], data, res);
          const agreementSignMatch = url.match(/^\/owner\/tenancy\/(\d+)\/agreement\/sign$/);
          if (agreementSignMatch) return handleSignTenancyAgreement(ownerId, agreementSignMatch[1], data, res);
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
          if (url === '/admin/support-staff')       return handleAddSupportStaff(data, res);
          const handoverMatch = url.match(/^\/admin\/payment\/([^/]+)\/handover$/);
          if (handoverMatch) return handleConfirmHandover(req, res, handoverMatch[1]);
          const staffRegenMatch = url.match(/^\/admin\/support-staff\/(\d+)\/regenerate$/);
          if (staffRegenMatch) return handleRegenerateSupportStaff(staffRegenMatch[1], res);
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
       COALESCE(monthly_rent,NULL) as monthly_rent,COALESCE(annual_rent,NULL) as annual_rent,COALESCE(nightly_rate,NULL) as nightly_rate,
       COALESCE(sale_price,NULL) as sale_price,COALESCE(lease_price,NULL) as lease_price,
       state,lga,address,img,COALESCE(images,'[]'::jsonb) as images,video_url,COALESCE(docs,'[]'::jsonb) as docs,
       COALESCE(bedrooms,NULL) as bedrooms,COALESCE(bathrooms,NULL) as bathrooms,COALESCE(size_sqm,NULL) as size_sqm,
       COALESCE(description,'') as description,COALESCE(amenities,'[]'::jsonb) as amenities,notes,created_at
       FROM properties WHERE id=$1 AND owner_id=$2`,
      [propId, ownerId]
    );
    if (!r.rows.length) return json(res, 404, { error: 'Property not found' });
    const prop = r.rows[0];
    try {
      const ur = await db.query("SELECT id,unit_label,unit_type,floor_level,capacity,monthly_price,status,COALESCE(images,'[]'::jsonb) as images,COALESCE(description,'') as description FROM property_units WHERE property_id=$1 ORDER BY unit_label", [propId]);
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

// ── Admin Refresh — POST /admin/refresh ──────────────────────────────────────
// Lets the client silently renew its token before the 8h window runs out, so
// an admin actively using the panel never gets a surprise hard-logout mid-
// session. Requires the CURRENT token to still be valid — this extends an
// active session, it can't resurrect one that's already expired or was
// signed with an old JWT_SECRET (e.g. after a secret rotation), which is
// intentional: that case should always require a real re-login.
async function handleAdminRefresh(req, res) {
  const payload = requireAdmin(req, res);
  if (!payload) return; // requireAdmin already sent the 401
  const token = jwtSign({ role: 'admin', email: payload.email || ADMIN_EMAIL }, JWT_SECRET, 8);
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

// Tenancy renewal/packing-out reminders — runs once shortly after boot (so a
// deploy/restart doesn't mean waiting a full day for the first check), then
// every 12 hours after that. A plain setInterval is fine here since Railway
// keeps this process running continuously — no external cron infrastructure
// needed.
setTimeout(() => { checkTenancyReminders().catch(e => console.error('Initial tenancy reminder check failed:', e.message)); }, 30000);
setInterval(() => { checkTenancyReminders().catch(e => console.error('Scheduled tenancy reminder check failed:', e.message)); }, 12 * 60 * 60 * 1000);
ensureSupportAccount();
ensureLastActiveColumn();
