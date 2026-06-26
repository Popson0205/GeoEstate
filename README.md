# GeoEstate API v2.0

Node.js + PostgreSQL (Neon) — Deployed on Railway

## Environment Variables (set in Railway dashboard)

| Variable | Description |
|---|---|
| `SECRET_NEON_DATABASE_URL` | Neon PostgreSQL connection string |
| `SECRET_RESEND_API_KEY` | Resend email API key |
| `ADMIN_SECRET` | Your admin token (keep secret — no default) |
| `CLOUDINARY_CLOUD_NAME` | (Optional) Cloudinary cloud name for image uploads |
| `CLOUDINARY_API_KEY` | (Optional) Cloudinary API key |
| `CLOUDINARY_API_SECRET` | (Optional) Cloudinary API secret |

## Deploy on Railway

1. Create a new Railway project → "Deploy from GitHub repo"
2. Select `Popson0205/GeoEstate`
3. Set the environment variables above
4. Railway auto-detects Node.js and runs `node server.js`
5. Add custom domain: `api.geoestate.com.ng` in Railway → Settings → Networking

## Database Setup

Run `schema.sql` on your Neon database once:

```bash
psql $SECRET_NEON_DATABASE_URL -f schema.sql
```

To wipe test/seed data from your Neon DB, run `clear-test-data.sql`:

```bash
psql $SECRET_NEON_DATABASE_URL -f clear-test-data.sql
```

## Admin Authentication

All `/admin/*` routes require:
```
Authorization: Bearer YOUR_ADMIN_SECRET
```

## Owner Authentication

1. `POST /owner/login` with `{ email }` → OTP sent
2. `POST /owner/login` with `{ email, code }` → returns `token`
3. Use token: `Authorization: Bearer owner:<userId>:<timestamp>`

## Health Check

`GET /health` — Returns `{ status: "ok" }`
