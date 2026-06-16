-- GeoEstate Platform — Complete Schema v2.0
-- Run this on your Neon PostgreSQL database to set up or migrate

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
  -- PHASE 2: Owner fields
  is_verified     BOOLEAN DEFAULT FALSE,
  owner_since     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS properties (
  id              TEXT PRIMARY KEY,
  title           TEXT NOT NULL,
  owner           TEXT,
  owner_id        TEXT REFERENCES registrations(id),
  -- PHASE 1: listing_type separates rent/buy/lease
  listing_type    TEXT DEFAULT 'rent' CHECK (listing_type IN ('rent','buy','lease')),
  type            TEXT DEFAULT 'rent',
  status          TEXT DEFAULT 'pending',
  -- Price fields by listing type
  price           TEXT,
  monthly_rent    NUMERIC,
  sale_price      NUMERIC,
  lease_price     NUMERIC,
  -- Property details
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

-- PHASE 3: Property units (rooms, flats, shops, etc.)
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
  notes               TEXT DEFAULT '',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PHASE 4: Enquiries
CREATE TABLE IF NOT EXISTS enquiries (
  id              TEXT PRIMARY KEY,
  property_id     TEXT REFERENCES properties(id),
  unit_id         INTEGER REFERENCES property_units(id),
  name            TEXT NOT NULL,
  email           TEXT NOT NULL,
  phone           TEXT DEFAULT '',
  message         TEXT DEFAULT '',
  status          TEXT DEFAULT 'new',
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

CREATE TABLE IF NOT EXISTS activity_log (
  id              SERIAL PRIMARY KEY,
  message         TEXT NOT NULL,
  logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- MIGRATION STATEMENTS (safe to run on existing DB)
-- ═══════════════════════════════════════════════════════

-- Add owner fields to existing registrations table
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS owner_since TIMESTAMPTZ;

-- Add listing_type and new price columns to properties
ALTER TABLE properties ADD COLUMN IF NOT EXISTS listing_type TEXT DEFAULT 'rent';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS monthly_rent NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS sale_price NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS lease_price NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS bedrooms INTEGER;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS bathrooms INTEGER;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS size_sqm NUMERIC;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS amenities JSONB DEFAULT '[]';

-- Backfill listing_type from type column
UPDATE properties SET listing_type = type WHERE listing_type IS NULL OR listing_type = '';

-- Add unit and tenant refs to tenancies
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS property_id TEXT;
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS unit_id INTEGER;
ALTER TABLE tenancies ADD COLUMN IF NOT EXISTS tenant_id TEXT;

-- Add tenancy_id to payments
ALTER TABLE payments ADD COLUMN IF NOT EXISTS tenancy_id INTEGER;

-- Add notes to disputes
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';

-- ═══════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_registrations_status ON registrations(status);
CREATE INDEX IF NOT EXISTS idx_registrations_email ON registrations(email);
CREATE INDEX IF NOT EXISTS idx_registrations_role ON registrations(role);
CREATE INDEX IF NOT EXISTS idx_properties_status ON properties(status);
CREATE INDEX IF NOT EXISTS idx_properties_listing_type ON properties(listing_type);
CREATE INDEX IF NOT EXISTS idx_properties_owner_id ON properties(owner_id);
CREATE INDEX IF NOT EXISTS idx_property_units_property_id ON property_units(property_id);
CREATE INDEX IF NOT EXISTS idx_property_units_status ON property_units(status);
CREATE INDEX IF NOT EXISTS idx_tenancies_end_date ON tenancies(end_date);
CREATE INDEX IF NOT EXISTS idx_tenancies_status ON tenancies(status);
CREATE INDEX IF NOT EXISTS idx_enquiries_property_id ON enquiries(property_id);
