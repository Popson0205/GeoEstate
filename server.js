// GeoEstate API Server — Render.com deployment
// Loads credentials from .env file (baked in at build time)
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
const FROM_EMAIL     = 'GeoEstate <noreply@geoestate.com.ng>';
const otpStore       = {}; // ephemeral — OTPs don't need to persist

// ── Helpers ──────────────────────────────────────────────────────────────────
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function json(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function sendEmail(to, subject, html) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ from: FROM_EMAIL, to: [to], subject, html });
    const req  = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
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

async function logActivity(msg) {
  try { await db.query('INSERT INTO activity_log (message) VALUES ($1)', [msg]); } catch(e) {}
}

// ── Route handlers ───────────────────────────────────────────────────────────
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

async function handleGetRegistrations(url, res) {
  try {
    const since = new URL('http://x' + url).searchParams.get('since');
    let q = 'SELECT * FROM registrations ORDER BY created_at DESC';
    const params = [];
    if (since) { q = 'SELECT * FROM registrations WHERE created_at > $1 ORDER BY created_at DESC'; params.push(new Date(parseInt(since))); }
    const result = await db.query(q, params);
    // Map snake_case to camelCase for admin compatibility
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
      nextOfKinPhone: r.next_of_kin_phone||'—'
    }));
    json(res, 200, { success: true, count: rows.length, registrations: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetProperties(res) {
  try {
    const result = await db.query('SELECT * FROM properties ORDER BY created_at DESC');
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
    const result = await db.query('SELECT * FROM tenancies ORDER BY end_date ASC');
    const rows = result.rows.map(r => ({
      id: r.id, ref: r.ref, type: r.type, property: r.property,
      tenant: r.tenant, phone: r.phone, owner: r.owner,
      amount: r.amount, start: r.start_date, end: r.end_date,
      status: r.status, packingOutDate: r.packing_out_date,
      renewedAt: r.renewed_at, vacatedAt: r.vacated_at, notes: r.notes
    }));
    json(res, 200, { success: true, tenancies: rows });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleAdminUpdate(url, data, res) {
  // PATCH /admin/registration/:id — update status/reviewer/notes
  const regMatch = url.match(/^\/admin\/registration\/([^/]+)$/);
  if (regMatch) {
    const id = regMatch[1];
    const { status, reviewer, notes } = data;
    try {
      await db.query(
        'UPDATE registrations SET status=$1, reviewer=$2, notes=$3, updated_at=NOW() WHERE id=$4',
        [status, reviewer||'Tom K.', notes||'', id]
      );
      await logActivity('Registration ' + status + ': ' + id);
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  // PATCH /admin/property/:id
  const propMatch = url.match(/^\/admin\/property\/([^/]+)$/);
  if (propMatch) {
    const id = propMatch[1];
    try {
      const fields = Object.entries(data).filter(([k]) => ['title','owner','type','status','price','state','lga','address','img','notes','lawyer_assigned'].includes(k));
      if (!fields.length) return json(res, 400, { error: 'No valid fields' });
      const sets = fields.map(([k],i) => `${k}=$${i+2}`).join(',');
      await db.query(`UPDATE properties SET ${sets},updated_at=NOW() WHERE id=$1`, [id, ...fields.map(([,v])=>v)]);
      await logActivity('Property updated: ' + id);
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  // PATCH /admin/tenancy/:id
  const tenMatch = url.match(/^\/admin\/tenancy\/([^/]+)$/);
  if (tenMatch) {
    const id = tenMatch[1];
    const { status, packing_out_date, renewed_at, vacated_at } = data;
    try {
      await db.query(
        'UPDATE tenancies SET status=$1, packing_out_date=$2, renewed_at=$3, vacated_at=$4, updated_at=NOW() WHERE id=$5',
        [status, packing_out_date||null, renewed_at||null, vacated_at||null, id]
      );
      json(res, 200, { success: true });
    } catch(e) { json(res, 500, { error: e.message }); }
    return;
  }

  json(res, 404, { error: 'Unknown admin update endpoint' });
}

async function handleSaveProperty(data, res) {
  const { id, title, owner, type, status, price, state, lga, address, img, notes, email } = data;
  if (!title) return json(res, 400, { error: 'Title required' });
  const propId = id || ('PROP-' + Date.now());
  try {
    await db.query(
      `INSERT INTO properties (id,title,owner,type,status,price,state,lga,address,img,notes,submitted)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO UPDATE SET title=$2,owner=$3,type=$4,status=$5,price=$6,state=$7,lga=$8,address=$9,img=$10,notes=$11,updated_at=NOW()`,
      [propId,title,owner||'',type||'rent',status||'pending',price||'',state||'',lga||'',address||'',img||'',notes||'',new Date().toLocaleString('en-NG')]
    );
    await logActivity((id ? 'Property updated: ' : 'Property added: ') + title);
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
  const { ref, type, property, tenant, phone, owner, amount, start, end, notes } = data;
  if (!property || !tenant || !end) return json(res, 400, { error: 'Property, tenant and end date required' });
  try {
    await db.query(
      `INSERT INTO tenancies (ref,type,property,tenant,phone,owner,amount,start_date,end_date,notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (ref) DO NOTHING`,
      [ref||('TEN-'+Date.now()),type||'rent',property,tenant,phone||'',owner||'',amount||0,start,end,notes||'']
    );
    await logActivity('Tenancy added: ' + ref + ' — ' + property);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteTeamMember(id, res) {
  try {
    await db.query('DELETE FROM team_members WHERE id=$1', [id]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteLawyer(id, res) {
  try {
    await db.query('DELETE FROM lawyers WHERE id=$1', [id]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteProperty(id, res) {
  try {
    await db.query("UPDATE properties SET status='rejected', updated_at=NOW() WHERE id=$1", [id]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleDeleteTenancy(id, res) {
  try {
    await db.query('DELETE FROM tenancies WHERE id=$1', [id]);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetActivityLog(res) {
  try {
    const result = await db.query('SELECT * FROM activity_log ORDER BY logged_at DESC LIMIT 50');
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
    await db.query('UPDATE disputes SET status=$1, lawyer_assigned=$2, npf_filed=$3 WHERE id=$4',
      [status||'active', lawyerAssigned||'', npfFiled||false, id]);
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
  const { ref, prop, buyer, phone, owner, ownerAcct, amount, fee, ownerAmt, status, notified } = data;
  if (!ref) return json(res, 400, { error: 'Payment ref required' });
  try {
    await db.query(
      `INSERT INTO payments (ref,prop,buyer,phone,owner,owner_acct,amount,fee,owner_amt,status,notified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (ref) DO UPDATE SET status=$10, notified=$11, confirmed_at=CASE WHEN $10='confirmed' THEN NOW()::text ELSE confirmed_at END`,
      [ref, prop||'', buyer||'', phone||'', owner||'', ownerAcct||'', amount||0, fee||0, ownerAmt||0, status||'pending', notified||'']
    );
    await logActivity('Payment ' + (status||'pending') + ': ' + ref);
    json(res, 200, { success: true });
  } catch(e) { json(res, 500, { error: e.message }); }
}

async function handleGetSync(res) {
  // Returns data the public website needs: live properties + approved users
  try {
    const [props, regs] = await Promise.all([
      db.query("SELECT id,title,owner,type,price,state,lga,address,img,geo FROM properties WHERE status='live' ORDER BY created_at DESC"),
      db.query("SELECT id,email FROM registrations WHERE status='approved'")
    ]);
    json(res, 200, {
      success: true,
      liveProperties: props.rows,
      approvedUserCount: regs.rows.length,
      approvedUserEmails: regs.rows.map(r => r.email),
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

// ── HTTP Server ───────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  const url = req.url.split('?')[0];

  // ── GET routes ──
  if (req.method === 'GET') {
    if (url === '/')                         return db.query('SELECT COUNT(*) FROM registrations').then(r => json(res,200,{status:'ok',service:'GeoEstate API',db:'neon',registrations:r.rows[0].count})).catch(()=>json(res,200,{status:'ok',service:'GeoEstate API'}));
    if (url === '/admin/registrations')      return handleGetRegistrations(req.url, res);
    if (url === '/admin/properties')         return handleGetProperties(res);
    if (url === '/admin/team')               return handleGetTeam(res);
    if (url === '/admin/lawyers')            return handleGetLawyers(res);
    if (url === '/admin/transactions')       return handleGetTransactions(res);
    if (url === '/admin/tenancies')          return handleGetTenancies(res);
    if (url === '/admin/activity')           return handleGetActivityLog(res);
    if (url === '/admin/disputes')           return handleGetDisputes(res);
    if (url === '/admin/payments')           return handleGetPayments(res);
    if (url === '/admin/sync')               return handleGetSync(res);
    return json(res, 404, { error: 'Not found' });
  }

  // ── DELETE routes ──
  if (req.method === 'DELETE') {
    const tmMatch = url.match(/^\/admin\/team\/(\d+)$/);
    if (tmMatch) return handleDeleteTeamMember(tmMatch[1], res);
    const lwMatch = url.match(/^\/admin\/lawyer\/(\d+)$/);
    if (lwMatch) return handleDeleteLawyer(lwMatch[1], res);
    const prMatch = url.match(/^\/admin\/property\/([^/]+)$/);
    if (prMatch) return handleDeleteProperty(prMatch[1], res);
    const disMatch = url.match(/^\/admin\/dispute\/([^/]+)$/);
    if (disMatch) return handleUpdateDispute(disMatch[1], data, res);
    const tnMatch = url.match(/^\/admin\/tenancy\/(\d+)$/);
    if (tnMatch) return handleDeleteTenancy(tnMatch[1], res);
    return json(res, 404, { error: 'Not found' });
  }

  // ── POST / PATCH routes ──
  if (req.method === 'POST' || req.method === 'PATCH') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const data = body ? JSON.parse(body) : {};
        if (url === '/send-otp')            return handleSendOTP(data, res);
        if (url === '/verify-otp')          return handleVerifyOTP(data, res);
        if (url === '/register')            return handleRegister(data, res);
        if (url === '/submit-property')     return handleSaveProperty(data, res);
        if (url === '/admin/save-lawyer')   return handleSaveLawyer(data, res);
        if (url === '/admin/save-team')     return handleSaveTeamMember(data, res);
        if (url === '/admin/save-tenancy')  return handleSaveTenancy(data, res);
        if (url.startsWith('/admin/registration/') || url.startsWith('/admin/property/') || url.startsWith('/admin/tenancy/'))
                                            return handleAdminUpdate(url, data, res);
        if (url === '/submit-dispute')          return handleSubmitDispute(data, res);
        if (url === '/admin/save-payment')      return handleSavePayment(data, res);
        if (url === '/admin/save-transaction')  return handleSaveTransaction(data, res);
        return json(res, 404, { error: 'Not found' });
      } catch(e) { json(res, 400, { error: 'Bad request: ' + e.message }); }
    });
    return;
  }

  json(res, 405, { error: 'Method not allowed' });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log('✅ GeoEstate API running on port ' + PORT + ' — ' + FROM_EMAIL));

// ── ADDED ROUTES: Disputes, Payments, Sync ───────────────────────────────────
// (appended by GeoEstate go-live patch)
