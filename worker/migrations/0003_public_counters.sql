-- Public visitor counter, per page and across the site.
-- Unique means one randomly identified browser, NOT one real person.
-- Only HMAC digests of browser-generated IDs are stored, not IP addresses.
CREATE TABLE IF NOT EXISTS public_page_stats (
  page TEXT PRIMARY KEY CHECK(page IN ('model','feniks','demo')),
  total_views INTEGER NOT NULL DEFAULT 0,
  first_counted_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS public_unique_browsers (
  visitor_hash TEXT PRIMARY KEY,
  first_seen_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS public_page_unique_browsers (
  page TEXT NOT NULL CHECK(page IN ('model','feniks','demo')),
  visitor_hash TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  PRIMARY KEY(page, visitor_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_page_browsers
ON public_page_unique_browsers(page);
