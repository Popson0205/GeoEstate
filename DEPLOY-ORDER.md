# GeoEstate — Deploy Order v2.1
## Railway (backend) + Railway (frontend nginx) + Supabase

---

## Files in This Patch

| File | Repo | What changed |
|------|------|-------------|
| `server.js` | GeoEstate (backend) | Owner JWT fix, upload-sign Supabase response, trailing-slash route strip, register returns submissionId on duplicate, verify-identity saves photo_url/id_doc_url |
| `schema.sql` | Run in Supabase SQL Editor | Adds photo_url, id_doc_url, other_doc_url, pass_hash, property_title columns |
| `geo-api.js` | GeoEstate2 (frontend) | ownerFetch no longer sends Content-Type on GET requests |
| `index.html` | GeoEstate2 | All Cloudinary upload functions replaced with Supabase PUT uploads |
| `owner-dashboard.html` | GeoEstate2 | ownerCloudinaryUpload replaced with Supabase PUT upload |
| `nginx.conf` | GeoEstate2 | Added `/owner-dashboard` route (was missing — nav links broke) |
| `_redirects` | GeoEstate2 | Added `/owner-dashboard` and `/owner` redirects |
| `.env.backend` | GeoEstate | Updated template with all required Railway variables |

---

## Step 1 — Supabase SQL (run once)

1. Go to Supabase Dashboard → SQL Editor → New query
2. Paste the full contents of `schema.sql` and click **Run**
3. Confirm you see tables: registrations, properties, enquiries, otp_codes, etc.

## Step 2 — Supabase Storage bucket (create once)

1. Supabase Dashboard → Storage → New bucket
2. Name: **`geoestate-docs`** (must match `SUPABASE_BUCKET` env var)
3. Set to **Public**
4. Allowed MIME: `image/*, application/pdf`

## Step 3 — Railway Environment Variables (GeoEstate backend)

Set these in Railway → GeoEstate project → Variables:

```
SUPABASE_DB_URL       = postgresql://postgres.REF:PASS@aws-0-REGION.pooler.supabase.com:6543/postgres
SUPABASE_URL          = https://YOURREF.supabase.co
SUPABASE_SERVICE_KEY  = eyJhbGci... (service_role key — NOT anon key)
SUPABASE_BUCKET       = geoestate-docs
ADMIN_EMAIL           = admin@geoestate.com.ng
ADMIN_PASSWORD        = <your password>
JWT_SECRET            = <64-char hex — generate: openssl rand -hex 32>
SECRET_RESEND_API_KEY = re_xxxx
```

## Step 4 — Deploy backend (GeoEstate repo)

```bash
cp server.js schema.sql /path/to/GeoEstate/
git add server.js schema.sql .env.backend
git commit -m "v2.1 patch: Supabase upload, owner JWT, route fixes"
git push origin main
```
Railway auto-deploys on push. Watch logs for:
```
✅ GeoEstate API v2.1 running on port 3000
```

Test: `curl https://api.geoestate.com.ng/health` → `{"status":"ok","version":"2.1"}`

## Step 5 — Deploy frontend (GeoEstate2 repo)

```bash
cp index.html owner-dashboard.html geo-api.js nginx.conf _redirects /path/to/GeoEstate2/
# Remove the duplicate geo-api_final.js (it is identical to geo-api.js)
rm /path/to/GeoEstate2/geo-api_final.js
git add index.html owner-dashboard.html geo-api.js nginx.conf _redirects
git rm geo-api_final.js
git commit -m "v2.1 patch: Supabase uploads, owner-dashboard route, geo-api fix"
git push origin main
```

---

## What Was Fixed (Bug List)

### Backend (server.js)
1. **Owner token was a fragile string** (`owner:<id>:<timestamp>`) — replaced with a proper HS256 JWT signed with `JWT_SECRET`. Existing sessions still accepted (backward-compat) until they expire.
2. **`/upload-sign` returned `signed_url` but owner-dashboard expected `upload_url`** — server now returns both field names pointing to the same URL. Frontend does a PUT (not multipart POST) directly to Supabase.
3. **`/register` returned `success: true` on duplicate email but no `submissionId`** — post-registration flow uses `submissionId` for `/owner/verify-identity`. Fixed to always return the existing user's ID.
4. **Trailing slash on routes caused 404** — e.g. `/admin/login/` returned "Not found". Router now strips trailing slash before matching.
5. **`handleOwnerVerifyIdentity` did not save `photo_url` / `id_doc_url`** from the identity form — now saves both storage URLs into the registrations row.
6. **`handleOwnerLogin` sent OTP email synchronously** — if Resend failed, the OTP was already in DB but the user got a 500. Fixed to fire-and-forget the email (same pattern as registration).

### Frontend (index.html, owner-dashboard.html)
7. **All upload functions used Cloudinary multipart POST** (`api_key`, `timestamp`, `signature` fields) — replaced with Supabase signed PUT. The `/upload-sign` endpoint now returns `upload_url` and `public_url`.
8. **`cloudinaryUpload`, `adminCloudinaryUpload`, `handlePropPhotosUpload`** — all rewritten as Supabase PUT uploads. Fallback to local FileReader data-URL preview if upload-sign is unavailable.

### Routing (nginx.conf, _redirects)
9. **`/owner-dashboard` URL linked from nav but had no nginx route** — added `location /owner-dashboard` pointing to `owner-dashboard.html`.

### Database (schema.sql)
10. **`photo_url`, `id_doc_url`, `other_doc_url`, `pass_hash`** columns missing from `registrations` table definition — added to schema and migration block.
11. **`property_title`** column missing from `enquiries` table definition — added.

### Duplicate file
12. **`geo-api_final.js`** is byte-for-byte identical to `geo-api.js` — remove it to avoid confusion. HTML pages only reference `geo-api.js`.

---

## Verification Checklist

After deploy, test these flows end-to-end:

- [ ] `GET https://api.geoestate.com.ng/health` → `{"status":"ok"}`
- [ ] `GET https://api.geoestate.com.ng/properties` → array of live listings
- [ ] Register a new user → OTP email arrives → account created
- [ ] Log in with email + password → user session set
- [ ] Visit `/owner-dashboard` → owner login page loads (not 404)
- [ ] Owner OTP login → JWT stored → dashboard loads
- [ ] Upload a photo on verify-identity form → Supabase Storage URL saved
- [ ] Admin login at `/admin` → JWT stored → all admin tabs load data
- [ ] Submit enquiry on a property → sales team receives email
