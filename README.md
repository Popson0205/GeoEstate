# GeoEstate API v2.0

Node.js + PostgreSQL (Neon) — Deployed on Render.com

## Setup

1. Set environment variables on Render:
   - `SECRET_NEON_DATABASE_URL` — your Neon connection string
   - `SECRET_RESEND_API_KEY` — your Resend API key
   - `ADMIN_SECRET` — your admin token (keep this secret)

2. Run `schema.sql` on your Neon database to apply migrations

3. Deploy: push to GitHub → Render auto-deploys

## Admin Authentication

All `/admin/*` routes require:
```
Authorization: Bearer YOUR_ADMIN_SECRET
```
or
```
X-Admin-Token: YOUR_ADMIN_SECRET
```

## Owner Authentication

1. POST `/owner/login` with `{ email }` → OTP sent
2. POST `/owner/login` with `{ email, code }` → returns `token`
3. Use token on all owner requests:
```
Authorization: Bearer owner:<userId>:<timestamp>
```

## New in v2.0

- ✅ Admin auth middleware on all /admin/* routes
- ✅ POST /admin/create-property (and /admin/save-property)
- ✅ GET /properties with ?type=rent|buy|lease filter
- ✅ GET /properties/:id (single property with units)
- ✅ Owner dashboard routes (/owner/*)
- ✅ One-time identity verification for owners
- ✅ Property units CRUD (/owner/property/:id/units)
- ✅ listing_type separation (rent/buy/lease)
- ✅ Enquiry system (POST /enquiry)
- ✅ Server-Sent Events (GET /events) for real-time sync
- ✅ Payment tracking with tenancy linkage
- ✅ Activity log broadcast via SSE
- ✅ node_modules removed from repo (.gitignore added)
