-- D1 extension: voluntary contact inquiries from thematic pages.
CREATE TABLE IF NOT EXISTS contact_requests(
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  source_page TEXT NOT NULL,
  interest TEXT NOT NULL,
  intent TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','read','closed')),
  consent_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contact_requests_created ON contact_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_contact_requests_status ON contact_requests(status,created_at);
