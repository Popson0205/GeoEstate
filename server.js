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

// ── DB Pool ──────────────────────────────────────────────────────────────────
process.env.NODE_NO_WARNINGS = "1";
const db = new Pool({
  connectionString: process.env.SECRET_NEON_DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Config ───────────────────────────────────────────────────────────────────
const RESEND_API_KEY = process.env.SECRET_RESEND_API_KEY;
const ADMIN_SECRET   = process.env.ADMIN_SECRET || 'geoestate-admin-2024';
const FROM_EMAIL     = 'GeoEstate <noreply@geoestate.com.ng>';
const otpStore       = {};
const sseClients     = new Set(); // for Server-Sent Events

// ── SSE Broadcast ─────────────────────────────────────────────────────────────
function broadcast(eventName, data) {
  const msg = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.write(msg); } catch(e) { sseClients.delete(client); }
  }
}

// ── Auth Middleware ───────────────────────────────────────────────────────────
function requireAdmin(req, res) {
  const auth = req.headers['authorization'] || req.headers['x-admin-token'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (token !== ADMIN_SECRET) {
    json(res, 401, { error: 'Unauthorized' });
    return false;
  }
  return true;
}

function requireOwner(req, res) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token || !token.startsWith('owner:')) {
    json(res, 401, { error: 'Owner authentication required' });
    return null;
  }
  return token.replace('owner:', '');
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
  otpStore[email.toLowerCase()] = { code, expires: Date.now() + 10 * 60 * 1000, attempts: 0 };
  try {
    await sendEmail(email, 'GeoEstate — Your Code: ' + code, otpEmail(code, name || '', purpose || 'register'));
    json(res, 200, { success: true, message: 'Code sent to ' + email });
  } catch(e) {
    console.error('Email error:', e.message);
    json(res, 500, { error: e.message });
  }
}

async function handleVerifyOTP(data, res) {
  const { email, code } = data;
  if (!email || !code) return json(res, 400, { error: 'Email and code required' });
  const record = otpStore[email.toLowerCase()];
  if (!record) return json(res, 400, { error: 'No code found. Request a new one.' });
  if (Date.now() > record.expires) { delete otpStore[email.toLowerCase()]; return json(res, 400, { error: 'Code expired.' }); }
  record.attempts++;
  if (record.attempts > 5) { delete otpStore[email.toLowerCase()]; return json(res, 429, { error: 'Too many attempts. Request a new code.' }); }
  if (code !== record.code) return json(res, 400, { error: 'Incorrect code. ' + (5 - record.attempts) + ' attempt(s) remaining.' });
  delete otpStore[email.toLowerCase()];
  json(res, 200, { success: true, message: 'Email verified' });
}

async function handleRegister(data, res) {
  const { fname, lname, email, phone, role, id, registeredAt } = data;
  if (!email || !fname) return json(res, 400, { error: 'Name and email required' });
  try {
    const exists = await db.query('SELECT id FROM registrations WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length) return json(res, 200, { success: true, message: 'Already registered' });
    const subId = id || ('USR-' + Date.now());
    await db.query(
      `INSERT INTO registrations (id,fname,lname,email,phone,role,type,status,submitted,registered_at,initials)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$10)`,
      [subId, fname, lname, email.toLowerCase(), phone||'', role||'renter', role||'renter',
       new Date().toLocaleString('en-NG'), registeredAt||new Date().toISOString(),
       (fname[0]||'')+(lname[0]||'')]
    );
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
    const type   = params.get('type');
    const state  = params.get('state');
    const search = params.get('q');
    let query  = "SELECT id,title,owner,owner_id,listing_type,type,status,price,monthly_rent,sale_price,lease_price,state,lga,address,img,images,bedrooms,bathrooms,size_sqm,description,amenities,created_at FROM properties WHERE status='live'";
    const args = [];
    if (type) { args.push(type); query += ` AND listing_type=$${args.length}`; }
    if (state) { args.push('%' + state + '%'); query += ` AND state ILIKE $${args.length}`; }
    if (search) { args.push('%' + search + '%'); query += ` AND (title ILIKE $${args.length} OR address ILIKE $${args.length} OR lga ILIKE $${args.length})`; }
    query += ' ORDER BY created_at DESC';
    const result = await db.query(query, args);
    json(res, 200, { success: true, count: result.rows.length, properties: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handlePublicPropertyById(id, res) {
  try {
    const r = await db.query(
      "SELECT p.*, array_agg(json_build_object('id',u.id,'label',u.unit_label,'type',u.unit_type,'floor',u.floor_level,'capacity',u.capacity,'price',u.monthly_price,'status',u.status,'occupied_since',u.occupied_since,'lease_end',u.lease_end)) FILTER (WHERE u.id IS NOT NULL) as units FROM properties p LEFT JOIN property_units u ON u.property_id=p.id WHERE p.id=$1 GROUP BY p.id",
      [id]
    );
    if (!r.rows.length) return json(res, 404, { error: 'Property not found' });
    json(res, 200, { success: true, property: r.rows[0] });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ── Admin GET routes ──
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
    const result = await db.query('SELECT *, COALESCE(listing_type, type) as listing_type FROM properties ORDER BY created_at DESC');
    json(res, 200, { success: true, count: result.rows.length, properties: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
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
        await db.query('UPDATE registrations SET is_verified=true WHERE id=$1 AND role=$2', [id, 'owner']);
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
      const allowed = ['title','owner','listing_type','type','status','price','monthly_rent','sale_price','lease_price','state','lga','address','img','images','bedrooms','bathrooms','size_sqm','description','amenities','notes','lawyer_assigned'];
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

  json(res, 404, { error: 'Unknown admin update endpoint' });
}

async function handleSaveProperty(data, res) {
  const { id, title, owner, owner_id, listing_type, type, status, price, monthly_rent, sale_price, lease_price, state, lga, address, img, images, bedrooms, bathrooms, size_sqm, description, amenities, notes } = data;
  if (!title) return json(res, 400, { error: 'Title required' });
  const propId = id || ('PROP-' + Date.now());
  const lt = listing_type || type || 'rent';
  try {
    await db.query(
      `INSERT INTO properties (id,title,owner,owner_id,listing_type,type,status,price,monthly_rent,sale_price,lease_price,state,lga,address,img,images,bedrooms,bathrooms,size_sqm,description,amenities,notes,submitted)
       VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
       ON CONFLICT (id) DO UPDATE SET title=$2,owner=$3,listing_type=$5,type=$5,status=$6,price=$7,monthly_rent=$8,sale_price=$9,lease_price=$10,state=$11,lga=$12,address=$13,img=$14,images=$15,bedrooms=$16,bathrooms=$17,size_sqm=$18,description=$19,amenities=$20,notes=$21,updated_at=NOW()`,
      [propId,title,owner||'',owner_id||null,lt,status||'pending',price||'',monthly_rent||null,sale_price||null,lease_price||null,state||'',lga||'',address||'',img||'',JSON.stringify(images||[]),bedrooms||null,bathrooms||null,size_sqm||null,description||'',JSON.stringify(amenities||[]),notes||'',new Date().toLocaleString('en-NG')]
    );
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
    await db.query('UPDATE disputes SET status=$1, lawyer_assigned=$2, npf_filed=$3, notes=COALESCE($4,notes) WHERE id=$5',
      [status||'active', lawyerAssigned||'', npfFiled||false, notes||null, id]);
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
       ON CONFLICT (ref) DO UPDATE SET status=$10, notified=$11, confirmed_at=CASE WHEN $10='confirmed' THEN NOW()::text ELSE confirmed_at END`,
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
      db.query("SELECT id,title,owner,listing_type,type,price,monthly_rent,sale_price,lease_price,state,lga,address,img,images,bedrooms,bathrooms,description,amenities FROM properties WHERE status='live' ORDER BY created_at DESC"),
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

  // If just requesting OTP
  if (!code) {
    const otpCode = generateOTP();
    otpStore['owner:' + email.toLowerCase()] = { code: otpCode, expires: Date.now() + 10 * 60 * 1000, attempts: 0 };
    try {
      await sendEmail(email, 'GeoEstate Owner Login — Code: ' + otpCode, otpEmail(otpCode, '', 'owner-login'));
      return json(res, 200, { success: true, message: 'Code sent' });
    } catch(e) { return json(res, 500, { error: e.message }); }
  }

  // Verify OTP
  const record = otpStore['owner:' + email.toLowerCase()];
  if (!record) return json(res, 400, { error: 'No code found. Request a new one.' });
  if (Date.now() > record.expires) { delete otpStore['owner:' + email.toLowerCase()]; return json(res, 400, { error: 'Code expired.' }); }
  record.attempts++;
  if (code !== record.code) return json(res, 400, { error: 'Incorrect code.' });
  delete otpStore['owner:' + email.toLowerCase()];

  // Find user
  try {
    const r = await db.query('SELECT * FROM registrations WHERE email=$1 AND role=$2', [email.toLowerCase(), 'owner']);
    if (!r.rows.length) return json(res, 404, { error: 'No owner account found for this email. Please register first.' });
    const u = r.rows[0];
    const token = 'owner:' + u.id + ':' + Date.now();
    json(res, 200, {
      success: true,
      token,
      owner: {
        id: u.id, fname: u.fname, lname: u.lname, email: u.email,
        phone: u.phone, is_verified: u.is_verified, owner_since: u.owner_since,
        status: u.status
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

    const { nin, doc_type, doc_url, selfie_url } = data;
    await db.query(
      'UPDATE registrations SET nin=$1, doc=$2, is_verified=false, status=$3, updated_at=NOW() WHERE id=$4',
      [nin||'', doc_type + '|' + (doc_url||''), 'review', ownerId]
    );
    await logActivity('Owner identity submitted for review: ' + ownerId);
    json(res, 200, { success: true, message: 'Identity submitted. You will be notified once verified (usually within 24 hours).' });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerProperties(ownerId, urlFull, res) {
  try {
    const params = new URL('http://x' + urlFull).searchParams;
    const type = params.get('type');
    let q = 'SELECT p.*, (SELECT COUNT(*) FROM property_units u WHERE u.property_id=p.id) as unit_count, (SELECT COUNT(*) FROM property_units u WHERE u.property_id=p.id AND u.status=\'vacant\') as vacant_units FROM properties p WHERE p.owner_id=$1';
    const args = [ownerId];
    if (type) { args.push(type); q += ` AND p.listing_type=$${args.length}`; }
    q += ' ORDER BY p.created_at DESC';
    const result = await db.query(q, args);
    json(res, 200, { success: true, properties: result.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleOwnerAddProperty(ownerId, data, res) {
  // Check verification
  const vr = await db.query('SELECT is_verified, status FROM registrations WHERE id=$1', [ownerId]);
  if (!vr.rows.length) return json(res, 404, { error: 'Owner not found' });
  if (!vr.rows[0].is_verified) return json(res, 403, {
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
    const r = await db.query('SELECT * FROM property_units WHERE property_id=$1 ORDER BY unit_label', [propId]);
    const stats = { total: r.rows.length, vacant: 0, occupied: 0, reserved: 0, maintenance: 0 };
    r.rows.forEach(u => { if (stats[u.status] !== undefined) stats[u.status]++; });
    json(res, 200, { success: true, units: r.rows, stats });
  } catch(e) { json(res, 500, { error: e.message }); }
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
    const r = await db.query('SELECT * FROM property_units WHERE property_id=$1 ORDER BY unit_label', [propId]);
    json(res, 200, { success: true, units: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

// ══════════════════════════════════════════════════════════════
// PHASE 4 — ENQUIRY, SEARCH, SSE
// ══════════════════════════════════════════════════════════════

async function handleEnquiry(data, res) {
  const { property_id, name, email, phone, message, unit_id } = data;
  if (!property_id || !name || !email) return json(res, 400, { error: 'property_id, name and email required' });
  const id = 'ENQ-' + Date.now();
  try {
    await db.query(
      'INSERT INTO enquiries (id,property_id,unit_id,name,email,phone,message) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, property_id, unit_id||null, name, email, phone||'', message||'']
    );
    // Notify owner
    const propR = await db.query('SELECT title, owner_id, (SELECT email FROM registrations WHERE id=properties.owner_id) as owner_email FROM properties WHERE id=$1', [property_id]);
    if (propR.rows[0]?.owner_email) {
      sendEmail(propR.rows[0].owner_email, '📬 New Enquiry: ' + propR.rows[0].title, enquiryEmail({name,email,phone,message}, propR.rows[0].title))
        .catch(e => console.warn('Enquiry email failed:', e.message));
    }
    await logActivity('Enquiry received for property ' + property_id + ' from ' + name);
    broadcast('new_enquiry', { property_id, name });
    json(res, 200, { success: true, enquiryId: id });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetAdminEnquiries(res) {
  try {
    const r = await db.query(`
      SELECT e.*, p.title as property_title, p.listing_type FROM enquiries e
      LEFT JOIN properties p ON p.id=e.property_id
      ORDER BY e.created_at DESC
    `);
    json(res, 200, { success: true, enquiries: r.rows });
  } catch(e) { json(res, 500, { error: e.message }); }
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

    // Public — no auth required
    if (url === '/properties')               return handlePublicProperties(urlFull, res);
    if (url.match(/^\/properties\/([^/]+)$/)) return handlePublicPropertyById(url.split('/')[2], res);
    if (url === '/events')                   return handleSSE(req, res);

    // Admin routes — require token
    if (url.startsWith('/admin/')) {
      if (!requireAdmin(req, res)) return;
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
        if (url === '/send-otp')             return handleSendOTP(data, res);
        if (url === '/verify-otp')           return handleVerifyOTP(data, res);
        if (url === '/register')             return handleRegister(data, res);
        if (url === '/enquiry')              return handleEnquiry(data, res);
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
          if (url.startsWith('/admin/registration/') || url.startsWith('/admin/property/') || url.startsWith('/admin/tenancy/'))
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

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log('✅ GeoEstate API v2.0 running on port ' + PORT));
