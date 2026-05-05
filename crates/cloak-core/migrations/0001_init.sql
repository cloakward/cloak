-- Cloak vault schema v1.
-- All tables are STRICT to enforce typed columns at the SQLite layer.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    format_version INTEGER NOT NULL,
    salt BLOB NOT NULL,
    kdf_phc TEXT NOT NULL,
    wrap_nonce BLOB NOT NULL,
    wrap_aead BLOB NOT NULL,
    monotonic_counter INTEGER NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    tags TEXT NOT NULL,            -- JSON array of strings
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
