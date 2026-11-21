-- Oracle portal: execute against a dedicated Cloudflare D1 database before deploying.
-- No API keys, admin secrets or private source documents belong here.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS guest_trials (
  credential_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used BETWEEN 0 AND 5),
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS login_challenges (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_requested_at INTEGER NOT NULL,
  day_id TEXT NOT NULL,
  day_requests INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_sessions (
  credential_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_daily_usage (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day_id TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id, day_id)
);

CREATE TABLE IF NOT EXISTS oracle_questions (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  identity_kind TEXT NOT NULL CHECK(identity_kind IN ('guest','member','legacy')),
  actor_hash TEXT,
  user_id TEXT,
  source_page TEXT,
  topic TEXT NOT NULL,
  question_length INTEGER NOT NULL,
  stored_with_consent INTEGER NOT NULL DEFAULT 0,
  question_text TEXT,
  answer_text TEXT,
  feedback INTEGER CHECK(feedback IS NULL OR feedback IN (-1,1)),
  input_tokens INTEGER,
  output_tokens INTEGER,
  outcome TEXT NOT NULL DEFAULT 'answered'
);
CREATE INDEX IF NOT EXISTS idx_oracle_questions_date ON oracle_questions(created_at);
CREATE INDEX IF NOT EXISTS idx_oracle_questions_topic ON oracle_questions(topic, created_at);
CREATE INDEX IF NOT EXISTS idx_oracle_questions_actor ON oracle_questions(actor_hash);
CREATE INDEX IF NOT EXISTS idx_oracle_questions_user ON oracle_questions(user_id);

CREATE TABLE IF NOT EXISTS portal_events (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  source_page TEXT
);
CREATE INDEX IF NOT EXISTS idx_portal_events_type_date ON portal_events(event_type,created_at);
