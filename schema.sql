-- GeoEstate Platform — Neon PostgreSQL Schema

-- Users / Registrations (identity queue)
CREATE TABLE IF NOT EXISTS registrations (
  id              TEXT PRIMARY KEY,
  fname           TEXT NOT NULL,
  lname           TEXT NOT NULL,
  email           TEXT NOT NULL UNIQUE,
  phone           TEXT,
  role            TEXT NOT NULL DEFAULT 'renter', -- 'owner' | 'renter'
  type            TEXT NOT NULL DEFAULT 'renter',
  status          TEXT NOT NULL DEFAULT 'pending', -- pending | review | approved | rejected | info
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
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Properties
CREATE TABLE IF NOT EXISTS properties (
  id              TEXT PRIMARY KEY,
  title           TEXT NOT NULL,
  owner           TEXT,
  owner_id        TEXT,
  type            TEXT DEFAULT 'rent', -- rent | buy | lease
  status          TEXT DEFAULT 'pending', -- pending | live | sold | rejected | review | info
  price           TEXT,
  state           TEXT,
  lga             TEXT,
  address         TEXT,
  img             TEXT,
  docs            JSONB DEFAULT '[]',
  geo             BOOLEAN DEFAULT TRUE,
  lawyer_req      BOOLEAN DEFAULT FALSE,
  lawyer_assigned TEXT,
  notes           TEXT DEFAULT '',
  submitted       TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lawyers
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

-- Team members
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

-- Tenancies
CREATE TABLE IF NOT EXISTS tenancies (
  id              SERIAL PRIMARY KEY,
  ref             TEXT UNIQUE,
  type            TEXT DEFAULT 'rent',
  property        TEXT,
  tenant          TEXT,
  phone           TEXT,
  owner           TEXT,
  amount          NUMERIC DEFAULT 0,
  start_date      DATE,
  end_date        DATE,
  status          TEXT DEFAULT 'active', -- active | renewed | packing-out | vacated | expired
  packing_out_date DATE,
  renewed_at      DATE,
  vacated_at      DATE,
  notes           TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Transactions
CREATE TABLE IF NOT EXISTS transactions (
  id              TEXT PRIMARY KEY,
  property        TEXT,
  buyer           TEXT,
  owner           TEXT,
  amount          TEXT,
  fee             TEXT,
  status          TEXT DEFAULT 'escrow', -- escrow | completed | disputed
  txn_date        DATE DEFAULT CURRENT_DATE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Manual payments
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
  status          TEXT DEFAULT 'pending', -- pending | confirmed | released | disputed
  notified        TEXT,
  confirmed_at    TEXT,
  released_at     TEXT,
  notes           TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Disputes
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
  filed           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Activity / sync log
CREATE TABLE IF NOT EXISTS activity_log (
  id              SERIAL PRIMARY KEY,
  message         TEXT NOT NULL,
  logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_registrations_status ON registrations(status);
CREATE INDEX IF NOT EXISTS idx_registrations_email ON registrations(email);
CREATE INDEX IF NOT EXISTS idx_properties_status ON properties(status);
CREATE INDEX IF NOT EXISTS idx_tenancies_end_date ON tenancies(end_date);
CREATE INDEX IF NOT EXISTS idx_tenancies_status ON tenancies(status);

