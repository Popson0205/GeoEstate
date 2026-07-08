-- GeoEstate — Add video_url column to properties
-- Run once on your Neon/Postgres database.
-- (images JSONB and docs JSONB already exist in schema.sql — this only adds video support.)

ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS video_url TEXT DEFAULT NULL;

-- Verify
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'properties'
  AND column_name IN ('video_url', 'images', 'docs');
