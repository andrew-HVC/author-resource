-- Optional semantic analytics consent for private collaboration threads.
-- All pre-existing conversations are EXCLUDED from text analytics by default.
-- Only the member controlling the verified thread may grant/revoke consent.
ALTER TABLE collaboration_threads ADD COLUMN analysis_consent INTEGER NOT NULL DEFAULT 0
  CHECK(analysis_consent IN (0,1));
ALTER TABLE collaboration_threads ADD COLUMN analysis_consented_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_collaboration_threads_analytics
  ON collaboration_threads(analysis_consent,updated_at);
