# GeoEstate — Supabase v2 Deploy Guide
## Registration & Verification Redesign

---

## What Changed in This Version

### Registration Form (Step 1)
Now collects **only**:
- First name, Last name
- Email *(OTP sent here)*
- Phone
- Password
- Profile photo *(optional)*

NIN, ID documents, Next of Kin, address — all moved to Step 2.

### Verify Identity Page (Step 2 — post-login)
Full form with proper IDs wired to `/owner/verify-identity`:
- DOB, Gender, Occupation, Employer
- State, LGA, Residential Address
- NIN (11-digit)
- Selfie photo upload → Supabase Storage
- Government ID document upload → Supabase Storage
- Next of Kin (name, relationship, phone)

### Backend (`server.js`)
- `handleOwnerVerifyIdentity` now saves `photo_url` + `id_doc_url` (Supabase Storage URLs)
- All 15 fields updated in a single SQL UPDATE with COALESCE (safe to re-submit)

### Post-login Banner
Amber banner appears after login for unverified users → links to Verify Identity page.

---

## Files in This Zip

| File | Repo | Notes |
|------|------|-------|
| `server.js` | GeoEstate (backend) | All fixes + Supabase storage + verify-identity fix |
| `index.html` | GeoEstate2 (frontend) | Simplified registration + full verify page + banner |
| `geo-api.js` | GeoEstate2 | Unchanged |
| `owner-dashboard.html` | GeoEstate2 | Unchanged |
| `sales.html` | GeoEstate2 | Unchanged |
| `supabase-schema.sql` | Supabase SQL Editor | Run once if not already done |

---

## Deploy Steps

### 1. Supabase SQL (only if not already run)
Run `supabase-schema.sql` in Supabase SQL Editor.
Confirm 13 tables + all columns including `photo_url`, `id_doc_url`, `nin`, `pass_hash`.

### 2. Supabase Storage Bucket (only if not already created)
Create bucket named exactly **`geoestate-docs`** → set to **Public**.

### 3. Railway Environment Variables (if not already set)
```
SUPABASE_DB_URL       = postgresql://postgres.REF:PASS@aws-0-REGION.pooler.supabase.com:5432/postgres
SUPABASE_URL          = https://YOURREF.supabase.co
SUPABASE_SERVICE_KEY  = eyJhbGci... (service_role key)
SUPABASE_BUCKET       = geoestate-docs
ADMIN_EMAIL           = (keep existing)
ADMIN_PASSWORD        = (keep existing)
JWT_SECRET            = (keep existing)
SECRET_RESEND_API_KEY = (keep existing)
```

### 4. Push `server.js` → GeoEstate repo → Railway auto-deploys

### 5. Push all frontend files → GeoEstate2 repo

---

## User Flow After Deploy

```
Visit site
  → Click Register
  → Enter: name + email + phone + password + optional photo
  → OTP sent to email
  → Enter OTP → Account created ✅
  → Automatically redirected to Verify Identity page
  → Fill: bio, NIN, selfie, ID doc, next of kin
  → Submit → status set to "review"
  → Admin reviews and approves
  → User gets full platform access
```

---

## Admin Dashboard After Verification
Once user submits verification, admin profile card will show:
- ✅ All personal bio data filled (not "—")
- ✅ NIN populated
- ✅ Selfie image displayed
- ✅ ID doc image/PDF displayed
- ✅ Next of kin filled
- Status: "review" (pending admin approval)
