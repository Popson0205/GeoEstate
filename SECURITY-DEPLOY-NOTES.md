# Security upgrade - deploy & rotation notes

## Deploy order (do these back-to-back)
1. Deploy backend (`server.js`).  2. Deploy frontend (all files in /frontend).
Between the two, registration from a cached old website shows "Email not verified" -
that's expected. Emergency rollback for that one check: set `ENFORCE_EMAIL_PROOF=false`.

## What users will notice
* Everyone is signed out once (old session tokens are no longer valid) - they just sign in again.
* Existing passwords keep working (auto-converted to salted hashes at boot / next login).
* Accounts that never had a password must use "Forgot password" once.
* "Forgot password" now really resets the password (code by email + new password).
* Old Android/iOS builds bundle the OLD website code: rebuild (`npx cap sync`) before release.

## Rotate these (an old commit, f513d58 from 7 June, contained a .env)
1. **Neon database password** - Neon dashboard -> Roles -> reset password for `neondb_owner`,
   then update `SUPABASE_DB_URL` in Railway.
2. **Resend API key** - create a new key, update `SECRET_RESEND_API_KEY`, delete the old key.
3. Set a fresh `JWT_SECRET` (`openssl rand -hex 32`) and a new `ADMIN_PASSWORD` in Railway.
4. If the repo was ever public: also treat the Supabase service key and any FCM key as exposed.
5. Remove files from tracking:  `git rm -r --cached node_modules .env.backend && git commit`
   (the history still has the old secrets - rotation is what protects you; optionally purge
   history with `git filter-repo`).

## Other env flags
* `ALLOW_DEV_OTP` must stay unset/false in production.
