# GeoEstate Fix — Deploy Order

## Files in this zip

| File | Repo | What changed |
|------|------|--------------|
| `server.js` | GeoEstate (backend) | NIN now saved to DB (Bug 2) |
| `index.html` | GeoEstate2 (frontend) | File upload non-blocking (Bug 1), SSE refresh (Bug 4), sendOTP fix (Bug 5) |
| `geo-api.js` | GeoEstate2 (frontend) | Unchanged |
| `owner-dashboard.html` | GeoEstate2 (frontend) | Unchanged |
| `sales.html` | GeoEstate2 (frontend) | Unchanged |
| `run-this-on-neon-first.sql` | Neon Console | Run BEFORE deploying server.js |

---

## Step 1 — Neon DB Migration (REQUIRED FIRST)

1. Go to [Neon Console](https://console.neon.tech)
2. Select your GeoEstate database
3. Click **SQL Editor**
4. Paste the contents of `run-this-on-neon-first.sql` and run it
5. Confirm you see **5 rows** returned (photo_url, id_doc_url, other_doc_url, pass_hash, nin)

---

## Step 2 — Deploy Backend (GeoEstate repo)

1. Replace `server.js` in your **GeoEstate** repo root
2. Push to GitHub → Railway auto-deploys (~60 seconds)

---

## Step 3 — Deploy Frontend (GeoEstate2 repo)

1. Replace `index.html`, `geo-api.js`, `owner-dashboard.html`, `sales.html` in your **GeoEstate2** repo root
2. Push to GitHub → deploys immediately

---

## What Was Fixed

| Bug | File | Description |
|-----|------|-------------|
| Bug 1 | index.html | File upload no longer BLOCKS registration — users without files can now register |
| Bug 2 | server.js | NIN is now saved to Neon DB (was silently dropped) |
| Bug 3 | Neon SQL | Missing columns `photo_url`, `id_doc_url`, `other_doc_url`, `pass_hash`, `nin` |
| Bug 4 | index.html | Admin dashboard now auto-refreshes via SSE when new registrations arrive |
| Bug 5 | index.html | OTP sent to correct email address (minor) |

---

## Verify After Deploy

```bash
# Check registration count increases
curl https://api.geoestate.com.ng/

# Test a registration (should return success + submissionId)
curl -X POST https://api.geoestate.com.ng/register \
  -H "Content-Type: application/json" \
  -d '{"fname":"Test","lname":"User","email":"yourtest@example.com","phone":"08012345678","role":"renter"}'
```
