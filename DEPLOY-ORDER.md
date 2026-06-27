# GeoEstate — Supabase Migration Guide

## What Changed
| Was | Now |
|-----|-----|
| Neon PostgreSQL | Supabase PostgreSQL (direct connection) |
| Cloudinary file storage | Supabase Storage |
| `SECRET_NEON_DATABASE_URL` env var | `SUPABASE_DB_URL` |
| `CLOUDINARY_CLOUD_NAME/API_KEY/SECRET` env vars | `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` |

No query rewrites — all `db.query()` calls are identical. Only the upload flow changed.

---

## Files in this zip

| File | Repo | Notes |
|------|------|-------|
| `server.js` | GeoEstate (backend) | All fixes + Supabase storage |
| `index.html` | GeoEstate2 (frontend) | All fixes + Supabase upload |
| `geo-api.js` | GeoEstate2 | Unchanged |
| `owner-dashboard.html` | GeoEstate2 | Unchanged |
| `sales.html` | GeoEstate2 | Unchanged |
| `supabase-schema.sql` | Supabase SQL Editor | Run this first |

---

## Step 1 — Supabase: Run the Schema

1. Go to [supabase.com](https://supabase.com) → your project
2. Click **SQL Editor** → **New Query**
3. Paste the full contents of `supabase-schema.sql` and click **Run**
4. Confirm you see **13 rows** returned at the end

---

## Step 2 — Supabase: Create Storage Bucket

1. In your Supabase project → **Storage** → **New Bucket**
2. Name it exactly: **`geoestate-docs`**
3. Set it to **Public** (so uploaded file URLs are accessible)
4. Click **Create**

---

## Step 3 — Supabase: Get Your Credentials

You need 3 values from Supabase:

### A. Database URL (for `SUPABASE_DB_URL`)
- Go to **Project Settings → Database**
- Under **Connection string**, select **URI**
- Choose **Transaction** mode (port `6543`) — works best on Railway
- Copy the full string:
  ```
  postgresql://postgres.[ref]:[YOUR-PASSWORD]@aws-0-[region].pooler.supabase.com:6543/postgres
  ```

### B. Project URL (for `SUPABASE_URL`)
- Go to **Project Settings → API**
- Copy **Project URL** — looks like:
  ```
  https://xxxxxxxxxxxx.supabase.co
  ```

### C. Service Role Key (for `SUPABASE_SERVICE_KEY`)
- Same page: **Project Settings → API**
- Under **Project API keys** → copy **service_role** (the long one)
- ⚠️ Keep this secret — never put it in frontend code

---

## Step 4 — Railway: Update Environment Variables

Go to your Railway project → GeoEstate service → **Variables** tab.

**Remove these:**
```
SECRET_NEON_DATABASE_URL
CLOUDINARY_CLOUD_NAME
CLOUDINARY_API_KEY
CLOUDINARY_API_SECRET
```

**Add these:**
```
SUPABASE_DB_URL       = postgresql://postgres.[ref]:[pass]@...pooler.supabase.com:6543/postgres
SUPABASE_URL          = https://xxxxxxxxxxxx.supabase.co
SUPABASE_SERVICE_KEY  = eyJhbGci....(long service_role key)
SUPABASE_BUCKET       = geoestate-docs
```

**Keep these unchanged:**
```
ADMIN_EMAIL
ADMIN_PASSWORD
JWT_SECRET
SECRET_RESEND_API_KEY
```

---

## Step 5 — Deploy Backend (GeoEstate repo)

1. Replace `server.js` in your GeoEstate repo root
2. Push to GitHub → Railway auto-deploys (~60 seconds)
3. Check Railway logs — should see:
   ```
   ✅ GeoEstate API v2.0 running on port ...
   ```

---

## Step 6 — Deploy Frontend (GeoEstate2 repo)

1. Replace `index.html`, `geo-api.js`, `owner-dashboard.html`, `sales.html`
2. Push to GitHub

---

## Step 7 — Verify Everything Works

**Test the API:**
```bash
curl https://api.geoestate.com.ng/
# Should return: {"status":"ok","registrations":"0",...}
```

**Test file upload:**
1. Go to geoestate.com.ng → Register
2. Upload a photo + ID doc
3. After registering, check **Supabase → Storage → geoestate-docs** — files should appear
4. Check **Supabase → Table Editor → registrations** — new row with `photo_url` filled in

---

## All Bug Fixes Included

| Bug | Description |
|-----|-------------|
| Bug 1 | File upload no longer blocks registration |
| Bug 2 | NIN now saved to database |
| Bug 3 | DB columns (photo_url, id_doc_url etc.) created in schema |
| Bug 4 | Admin dashboard auto-refreshes on new registration |
| Bug 5 | OTP sent to correct email |
