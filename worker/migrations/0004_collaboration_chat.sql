-- Private, email-verified collaboration conversations.
-- Apply after 0001_oracle_portal.sql, 0002_contacts.sql, 0003_public_counters.sql.
-- Existing unauthenticated contact_requests are NOT automatically associated by email.
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS collaboration_threads (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_page TEXT NOT NULL CHECK(source_page IN ('model','feniks','demo','oracle')),
  interest TEXT NOT NULL,
  intent TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  member_read_seq INTEGER NOT NULL DEFAULT 0,
  admin_read_seq INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed'))
);
CREATE INDEX IF NOT EXISTS idx_collaboration_threads_owner
  ON collaboration_threads(user_id,updated_at);
CREATE INDEX IF NOT EXISTS idx_collaboration_threads_admin
  ON collaboration_threads(updated_at);

CREATE TABLE IF NOT EXISTS collaboration_messages (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  thread_id TEXT NOT NULL REFERENCES collaboration_threads(id) ON DELETE CASCADE,
  sender TEXT NOT NULL CHECK(sender IN ('member','admin')),
  message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 5000),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_collaboration_messages_thread
  ON collaboration_messages(thread_id,seq);
CREATE INDEX IF NOT EXISTS idx_collaboration_messages_sender
  ON collaboration_messages(thread_id,sender,seq);
