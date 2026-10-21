-- SQLite migration for a local tool: SQLite has no Row Level Security, so the Supabase rules must not apply.
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL
);
