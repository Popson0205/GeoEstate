-- GeoEstate Platform — Complete Schema v2.1 (Supabase)
-- Run this in the Supabase SQL Editor (Dashboard → SQL Editor → New Query).
-- Every statement uses CREATE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS —
-- safe to re-run on an existing database without data loss.

-- ═══════════════════════════════════════════════════════
-- CORE TABLES
-- ═══════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS registrations (
  id              TEXT PRIMARY KEY,
  fname           TEXT NOT NULL,
  lname           TEXT NOT NULL,
  email           TEXT NOT NULL UNIQUE,
  phone           TEXT,
  role            TEXT NOT NULL DEFAULT 'renter',
  type            TEXT NOT NULL DEFAULT 'renter',
  status          TEXT NOT NULL DEFAULT 'pending',
  submitted       TEXT,
  registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sla_h           INTEGER DEFAULT 0,
  reviewer        TEXT DEFAULT 'Unassigned',
  initials        TEXT,
  dob             TEXT DEFAULT '—',
  gender          TEXT DEFAULT '—',
  occupation      TEXT DEFAULT '—',
  employer        TEXT DEFAULT '—',
  state           TEXT DEFAULT '—',
  lga             TEXT DEFAULT '—',
  address         TEXT DEFAULT '—',
  nin             TEXT DEFAULT '***-***-****',
  doc             TEXT DEFAULT 'Pending upload',
  notes           TEXT DEFAULT '',
  next_of_kin     TEXT DEFAULT '—',
  next_of_kin_rel TEXT DEFAULT '—',
  next_of_kin_phone TEXT DEFAULT '—',
  -- Owner verification fields
  is_verified     BOOLEAN DEFAULT FALSE,
  owner_since     TIMESTAMPTZ,
  -- Upload URLs (Supabase Storage)
  photo_url       TEXT DEFAULT NULL,
  id_doc_url      TEXT DEFAULT NULL,
  other_doc_url   TEXT DEFAULT NULL,
  -- Password hash (base64 of raw password — set on first login)
  pass_hash       TEXT DEFAULT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS properties (
  id              TEXT PRIMARY KEY,
  title           TEXT NOT NULL,
  owner           TEXT,
  owner_id        TEXT REFERENCES registrations(id),
  listing_type    TEXT DEFAULT 'rent' CHECK (listing_type IN ('rent','buy','lease')),
  type            TEXT DEFAULT 'rent',
  status          TEXT DEFAULT 'pending',
  price           TEXT,
  monthly_rent    NUMERIC,
  sale_price      NUMERIC,
  lease_price     NUMERIC,
  state           TEXT,
  lga             TEXT,
  address         TEXT,
  img             TEXT,
  images          JSONB DEFAULT '[]',
  bedrooms        INTEGER,
  bathrooms       INTEGER,
  size_sqm        NUMERIC,
  description     TEXT DEFAULT '',
  amenities       JSONB DEFAULT '[]',
  docs            JSONB DEFAULT '[]',
  geo             BOOLEAN DEFAULT TRUE,
  lawyer_req      BOOLEAN DEFAULT FALSE,
  lawyer_assigned TEXT,
  notes           TEXT DEFAULT '',
  submitted       TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS property_units (
  id                  SERIAL PRIMARY KEY,
  property_id         TEXT REFERENCES properties(id) ON DELETE CASCADE,
  unit_label          VARCHAR(100) NOT NULL,
  unit_type           VARCHAR(50) DEFAULT 'room',
  floor_level         VARCHAR(20) DEFAULT '',
  capacity            INTEGER DEFAULT 1,
  monthly_price       NUMERIC,
  status              VARCHAR(20) DEFAULT 'vacant' CHECK (status IN ('vacant','occupied','reserved','maintenance')),
  current_tenant_id   TEXT REFERENCES registrations(id),
  occupied_since      DATE,
  lease_end           DATE,
  images              JSONB DEFAULT '[]',
  description         TEXT DEFAULT '',
  notes               TEXT DEFAULT '',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS enquiries (
  id              TEXT PRIMARY KEY,
  property_id     TEXT REFERENCES properties(id),
  unit_id         INTEGER REFERENCES property_units(id),
  name            TEXT NOT NULL,
  email           TEXT NOT NULL,
  phone           TEXT DEFAULT '',
  message         TEXT DEFAULT '',
  status          TEXT DEFAULT 'new',
  notes           TEXT DEFAULT '',
  assigned_to     TEXT DEFAULT '',
  -- Cached property title so enquiry is readable even if property deleted
  property_title  TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lawyers (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  bar             TEXT,
  spec            TEXT,
  state           TEXT,
  email           TEXT,
  phone           TEXT,
  cases           INTEGER DEFAULT 0,
  done            INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'active',
  photo           TEXT DEFAULT '',
  bio             TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS team_members (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  role            TEXT,
  phone           TEXT,
  email           TEXT,
  photo           TEXT DEFAULT '',
  status          TEXT DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenancies (
  id              SERIAL PRIMARY KEY,
  ref             TEXT UNIQUE,
  type            TEXT DEFAULT 'rent',
  property        TEXT,
  property_id     TEXT REFERENCES properties(id),
  unit_id         INTEGER REFERENCES property_units(id),
  tenant          TEXT,
  tenant_id       TEXT REFERENCES registrations(id),
  phone           TEXT,
  owner           TEXT,
  amount          NUMERIC DEFAULT 0,
  start_date      DATE,
  end_date        DATE,
  status          TEXT DEFAULT 'active',
  packing_out_date DATE,
  renewed_at      DATE,
  vacated_at      DATE,
  notes           TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
  id              TEXT PRIMARY KEY,
  property        TEXT,
  buyer           TEXT,
  owner           TEXT,
  amount          TEXT,
  fee             TEXT,
  status          TEXT DEFAULT 'escrow',
  txn_date        DATE DEFAULT CURRENT_DATE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payments (
  id              SERIAL PRIMARY KEY,
  ref             TEXT UNIQUE,
  prop            TEXT,
  buyer           TEXT,
  phone           TEXT,
  owner           TEXT,
  owner_acct      TEXT,
  amount          NUMERIC DEFAULT 0,
  fee             NUMERIC DEFAULT 0,
  owner_amt       NUMERIC DEFAULT 0,
  status          TEXT DEFAULT 'pending',
  notified        TEXT,
  confirmed_at    TEXT,
  released_at     TEXT,
  tenancy_id      INTEGER REFERENCES tenancies(id),
  unit_id         INTEGER REFERENCES property_units(id),
  property_id     TEXT REFERENCES properties(id),
  notes           TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS disputes (
  id              TEXT PRIMARY KEY,
  title           TEXT,
  property        TEXT,
  complainant     TEXT,
  complainant_id  TEXT,
  respondent      TEXT,
  respondent_id   TEXT,
  amount          TEXT,
  description     TEXT,
  severity        TEXT DEFAULT 'medium',
  status          TEXT DEFAULT 'active',
  npf_filed       BOOLEAN DEFAULT FALSE,
  lawyer_assigned TEXT,
  notes           TEXT DEFAULT '',
  filed           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Real in-app notification center — the "Notifications" tab on both
-- platforms previously read from a localStorage key nothing ever wrote to.
-- Also doubles as the push-notification trigger point (see
-- createNotification() in server.js), so every notification type only
-- needs to be wired up once to cover both in-app and push delivery.
CREATE TABLE IF NOT EXISTS notifications (
  id          SERIAL PRIMARY KEY,
  user_id     TEXT NOT NULL,
  type        TEXT NOT NULL,
  title       TEXT NOT NULL,
  body        TEXT DEFAULT '',
  data        JSONB DEFAULT '{}',
  read_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS activity_log (
  id              SERIAL PRIMARY KEY,
  message         TEXT NOT NULL,
  logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OTP codes stored in DB (survive Railway restarts / multi-instance deploys)
CREATE TABLE IF NOT EXISTS otp_codes (
  key             TEXT PRIMARY KEY,
  code            TEXT NOT NULL,
  expires         TIMESTAMPTZ NOT NULL,
  attempts        INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Admin login audit log
CREATE TABLE IF NOT EXISTS admin_sessions (
  id          SERIAL PRIMARY KEY,
  email       TEXT NOT NULL,
  action      TEXT NOT NULL DEFAULT 'login',
  ip          TEXT,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- MIGRATION — safe to run on existing databases
-- ═══════════════════════════════════════════════════════

-- Owner verification columns
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS is_verified     BOOLEAN DEFAULT FALSE;
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS owner_since     TIMESTAMPTZ;
-- Powers chat "delivered" status (see requireOwner/handleGetThread) —
-- updated on every authenticated request, not just message-related ones.
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS last_active_at  TIMESTAMPTZ;

-- Supabase Storage upload URLs (v2.1 — replaces old Cloudinary fields)
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS photo_url       TEXT DEFAULT NULL;
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS id_doc_url      TEXT DEFAULT NULL;
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS other_doc_url   TEXT DEFAULT NULL;

-- Password hash (base64 of raw password, set on first login)
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS pass_hash       TEXT DEFAULT NULL;

-- Property listing_type and price breakdowns
ALTER TABLE properties ADD COLUMN IF NOT EXISTS listing_type   TEXT DEFAULT 'rent';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS monthly_rent   NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS sale_price     NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS lease_price    NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS images         JSONB DEFAULT '[]';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS bedrooms       INTEGER;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS bathrooms      INTEGER;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS size_sqm       NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS description    TEXT DEFAULT '';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS amenities      JSONB DEFAULT '[]';

-- Per-unit photos and description, so individual rooms/flats/units within a
-- multi-unit property (hotel rooms, self-cons, 2-bed vs 3-bed flats, etc.)
-- can each have their own image and write-up, not just a label and price.
ALTER TABLE property_units ADD COLUMN IF NOT EXISTS images      JSONB DEFAULT '[]';
ALTER TABLE property_units ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';

-- Second verification tier, distinct from owner identity verification
-- (registrations.is_verified). A physical site visit is a much stronger
-- trust signal than an ID check alone, especially for higher-value sales.
ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_date     DATE;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS site_visit_notes    TEXT DEFAULT '';

-- Simple per-property view counter for the owner analytics dashboard —
-- a single incrementing counter rather than a full events table, since
-- "roughly how many people looked at this listing" is what an owner
-- actually wants, not a detailed audit trail.
ALTER TABLE properties ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0;

-- Digital signature capture for tenancy agreements. This is a typed-name
-- signature + timestamp, a widely-used and generally accepted e-signature
-- pattern (similar to what many document-signing platforms use), NOT a
-- full certificate-based e-signature system — legal validity of a typed
-- signature varies by jurisdiction and use case, so this doesn't claim to
-- replace professional legal counsel for high-stakes agreements. One
-- agreement per tenancy.
CREATE TABLE IF NOT EXISTS tenancy_agreements (
  id                SERIAL PRIMARY KEY,
  tenancy_id        INTEGER NOT NULL REFERENCES tenancies(id) ON DELETE CASCADE UNIQUE,
  content           TEXT NOT NULL,
  owner_signature   TEXT,
  owner_signed_at   TIMESTAMPTZ,
  tenant_signature  TEXT,
  tenant_signed_at  TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Individually-enrolled staff logins for the shared "GeoEstate Support"
-- chat inbox — each row is one person's own TOTP (authenticator app)
-- credential; a successful login against any non-revoked row here issues
-- a token for SUPPORT_USER_ID, so the chat/messages model itself never
-- needs to know about individual staff at all.
CREATE TABLE IF NOT EXISTS support_staff (
  id             SERIAL PRIMARY KEY,
  name           TEXT NOT NULL,
  email          TEXT NOT NULL UNIQUE,
  totp_secret    TEXT NOT NULL,
  revoked        BOOLEAN DEFAULT FALSE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at  TIMESTAMPTZ
);

-- Lets a confirmed payment be traced back to the exact unit/property it was
-- for, so confirming it can automatically create a Tenancy Tracker record
-- (see handleSavePayment) instead of requiring a separate manual entry.
ALTER TABLE payments ADD COLUMN IF NOT EXISTS unit_id     INTEGER REFERENCES property_units(id);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS property_id TEXT REFERENCES properties(id);

-- Backfill listing_type from type column on existing rows
UPDATE properties SET listing_type = type WHERE listing_type IS NULL OR listing_type = '';

-- Tenancy foreign keys (added v2)
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS property_id TEXT;
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS unit_id     INTEGER;
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS tenant_id   TEXT;

-- Tracks whether each stage of the renewal/packing-out policy reminder
-- (2 months before expiry, 2 weeks before, and on expiry itself) has
-- already been emailed, so the scheduled reminder check never sends the
-- same stage twice for the same tenancy.
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS reminder_2mo_sent     BOOLEAN DEFAULT FALSE;
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS reminder_2wk_sent     BOOLEAN DEFAULT FALSE;
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS reminder_expiry_sent  BOOLEAN DEFAULT FALSE;

-- Payment → tenancy link
ALTER TABLE payments ADD COLUMN IF NOT EXISTS tenancy_id INTEGER;

-- Dispute notes
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';

-- Enquiry tracking columns
ALTER TABLE enquiries ADD COLUMN IF NOT EXISTS notes           TEXT DEFAULT '';
ALTER TABLE enquiries ADD COLUMN IF NOT EXISTS assigned_to     TEXT DEFAULT '';
ALTER TABLE enquiries ADD COLUMN IF NOT EXISTS property_title  TEXT DEFAULT '';

-- ═══════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_registrations_status      ON registrations(status);
CREATE INDEX IF NOT EXISTS idx_registrations_email       ON registrations(email);
CREATE INDEX IF NOT EXISTS idx_registrations_role        ON registrations(role);
CREATE INDEX IF NOT EXISTS idx_properties_status         ON properties(status);
CREATE INDEX IF NOT EXISTS idx_properties_listing_type   ON properties(listing_type);
CREATE INDEX IF NOT EXISTS idx_properties_owner_id       ON properties(owner_id);
CREATE INDEX IF NOT EXISTS idx_property_units_property   ON property_units(property_id);
CREATE INDEX IF NOT EXISTS idx_property_units_status     ON property_units(status);
CREATE INDEX IF NOT EXISTS idx_tenancies_end_date        ON tenancies(end_date);
CREATE INDEX IF NOT EXISTS idx_tenancies_status          ON tenancies(status);
CREATE INDEX IF NOT EXISTS idx_enquiries_property_id     ON enquiries(property_id);
CREATE INDEX IF NOT EXISTS idx_enquiries_status          ON enquiries(status);
CREATE INDEX IF NOT EXISTS idx_otp_codes_expires         ON otp_codes(expires);

-- ═══════════════════════════════════════════════════════
-- SUPABASE STORAGE — run this once in the Supabase Dashboard
-- ═══════════════════════════════════════════════════════
-- 1. Go to Storage → New bucket
-- 2. Name: geoestate-docs
-- 3. Set to PUBLIC (so URLs work without auth tokens)
-- 4. Allowed MIME types: image/*, application/pdf
--
-- The bucket name must match the SUPABASE_BUCKET env var on Railway
-- (default: geoestate-docs).
