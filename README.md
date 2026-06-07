# GeoEstate API Server

## Deploy to Render.com (Free)

1. Go to https://render.com → Sign up/login
2. Click **New** → **Web Service**
3. Connect your GitHub account → Upload this folder as a repo
   OR use **Deploy from existing repo** if you push this to GitHub
4. Set these Environment Variables in Render dashboard:
   - `SECRET_RESEND_API_KEY` = your Resend API key (re_xxx...)
   - `SECRET_NEON_DATABASE_URL` = your Neon connection string (postgresql://...)
5. Click **Deploy**
6. Your API URL will be: https://geoestate-api.onrender.com

## Endpoints
- GET  /                    → health check
- POST /send-otp            → send email OTP
- POST /verify-otp          → verify OTP code
- POST /register            → save new user registration
- GET  /admin/registrations → get all registrations
- GET  /admin/properties    → get all properties
- GET  /admin/team          → get team members
- GET  /admin/lawyers       → get lawyers
- GET  /admin/transactions  → get transactions
- GET  /admin/tenancies     → get tenancies
- POST /admin/save-lawyer   → add/update lawyer
- POST /admin/save-team     → add/update team member
- POST /admin/save-tenancy  → add tenancy record
- PATCH /admin/registration/:id → update registration status
- PATCH /admin/property/:id     → update property
