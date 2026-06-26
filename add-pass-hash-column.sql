-- GeoEstate — Add pass_hash column to registrations
-- Run this on your Neon database ONCE before deploying the updated server.js
-- This enables email + password login for registered users

ALTER TABLE registrations
  ADD COLUMN IF NOT EXISTS pass_hash TEXT DEFAULT NULL;

-- Verify
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'registrations'
  AND column_name = 'pass_hash';
