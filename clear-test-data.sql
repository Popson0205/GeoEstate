-- ═══════════════════════════════════════════════════════════════════════
-- GeoEstate — Clear All Test / Seed Data
-- ═══════════════════════════════════════════════════════════════════════
-- Run this on your Neon database to wipe all seeded/test data.
-- Real owner/team records in server.js code are NOT affected.
--
-- Usage:
--   psql $SECRET_NEON_DATABASE_URL -f clear-test-data.sql
--
-- ⚠️  This is DESTRUCTIVE. Back up your DB before running.
-- ═══════════════════════════════════════════════════════════════════════

BEGIN;

-- 1. Delete all seed properties (SEED-001 through SEED-008 and any test ones)
DELETE FROM property_units
WHERE property_id IN (
    SELECT id FROM properties
    WHERE id ILIKE 'SEED-%'
       OR title ILIKE '%test%'
       OR title ILIKE '%sample%'
       OR status = 'rejected'
);

DELETE FROM properties
WHERE id ILIKE 'SEED-%'
   OR title ILIKE '%test%'
   OR title ILIKE '%sample%'
   OR status = 'rejected';

-- 2. Delete test/E2E registrations
DELETE FROM tenancies      WHERE tenant_id IN (SELECT id FROM registrations WHERE id ILIKE '%E2E%' OR email ILIKE '%e2etest%' OR email ILIKE '%test%');
DELETE FROM payments       WHERE tenancy_id IN (SELECT id FROM tenancies WHERE tenant_id IN (SELECT id FROM registrations WHERE id ILIKE '%E2E%' OR email ILIKE '%e2etest%'));
DELETE FROM registrations  WHERE id ILIKE '%E2E%' OR email ILIKE '%e2etest%' OR email ILIKE '%test%';

-- 3. Delete test enquiries
DELETE FROM enquiries
WHERE name ILIKE '%E2E%'
   OR name ILIKE 'Test%'
   OR name ILIKE 'Test User'
   OR name ILIKE '%testuser%'
   OR status = 'closed';

-- 4. Delete test disputes
DELETE FROM disputes
WHERE title ILIKE 'Test Dispute%'
   OR title ILIKE 'Test%';

-- 5. Wipe OTP codes table (all OTPs are short-lived anyway)
DELETE FROM otp_codes;

-- 6. Clear activity log of seed/test events
DELETE FROM activity_log
WHERE action ILIKE '%seed%'
   OR action ILIKE '%purge%'
   OR action ILIKE '%test%'
   OR action ILIKE '%E2E%';

-- Show summary
SELECT
    (SELECT COUNT(*) FROM properties)    AS properties_remaining,
    (SELECT COUNT(*) FROM registrations) AS registrations_remaining,
    (SELECT COUNT(*) FROM enquiries)     AS enquiries_remaining,
    (SELECT COUNT(*) FROM otp_codes)     AS otp_codes_remaining,
    (SELECT COUNT(*) FROM tenancies)     AS tenancies_remaining;

COMMIT;
