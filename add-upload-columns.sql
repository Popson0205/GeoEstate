-- GeoEstate — Add Cloudinary upload columns to registrations
-- Run once on your Neon database

ALTER TABLE registrations
  ADD COLUMN IF NOT EXISTS photo_url     TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS id_doc_url    TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS other_doc_url TEXT DEFAULT NULL;

-- Verify
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'registrations'
  AND column_name IN ('photo_url', 'id_doc_url', 'other_doc_url');
