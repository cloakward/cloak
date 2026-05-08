//! SQLite-backed storage layer for the vault.
//!
//! - WAL journal mode (concurrent reads, single writer).
//! - `synchronous = NORMAL` (fast + durable enough; full WAL fsyncs at
//!   checkpoint).
//! - `foreign_keys = ON` (defense in depth even though current schema
//!   has no FK relationships yet).
//! - All tables are `STRICT`.
//!
//! Migrations are forward-only; each `NNNN_*.sql` file is recorded in the
//! `schema_migrations` table once applied.

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::error::{Error, Result};

/// Embedded migration scripts, in apply order.
const MIGRATIONS: &[(u32, &str, &str)] = &[
    (1, "0001_init", include_str!("../migrations/0001_init.sql")),
    (
        2,
        "0002_recovery_wrap",
        include_str!("../migrations/0002_recovery_wrap.sql"),
    ),
];

/// Newtype around a `rusqlite::Connection` for the vault DB.
pub struct SqliteStore {
    conn: Connection,
}

/// Raw row read from the `meta` table.
#[derive(Debug, Clone)]
pub struct MetaRow {
    /// Vault format version (currently 1).
    pub format_version: u32,
    /// 16-byte Argon2id salt.
    pub salt: [u8; 16],
    /// PHC string encoding the KDF parameters and salt (redundant with
    /// `salt` for self-description).
    pub kdf_phc: String,
    /// 24-byte nonce used to wrap the master key.
    pub wrap_nonce: [u8; 24],
    /// AEAD-wrapped master key (`ct || tag`).
    pub wrap_aead: Vec<u8>,
    /// Monotonic counter; rejects rollback.
    pub monotonic_counter: u64,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Discriminator for the recovery-wrap format. Currently only
    /// `"bip39-v1"` is defined: 24-word English mnemonic, BIP-39 seed
    /// (PBKDF2-HMAC-SHA512, 2048 iterations, empty BIP-39 passphrase),
    /// first 32 bytes used as the recovery key. `None` on vaults that
    /// pre-date the BIP-39 recovery migration (v0.9.0-rc3 and earlier).
    pub recovery_format: Option<String>,
    /// 24-byte AEAD nonce wrapping the master key under the recovery key.
    pub recovery_wrap_nonce: Option<[u8; 24]>,
    /// AEAD-wrapped master key (`ct || tag`) under the recovery key.
    pub recovery_wrap_aead: Option<Vec<u8>>,
}

/// Raw row read from `secrets` (without decoding the JSON tags).
#[derive(Debug, Clone)]
pub struct SecretRow {
    /// SQLite rowid; used as the per-record subkey id.
    pub id: i64,
    /// User-visible secret name.
    pub name: String,
    /// `SecretKind` as a stable lowercase string.
    pub kind: String,
    /// JSON-encoded array of tag strings.
    pub tags_json: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 last-update timestamp.
    pub updated_at: String,
    /// Monotonic record version.
    pub version: u64,
    /// 24-byte AEAD nonce.
    pub nonce: [u8; 24],
    /// Ciphertext including the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl SqliteStore {
    /// Open or create the SQLite vault file at `path`. Sets WAL mode and
    /// applies any pending forward migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        // Pragmas. `journal_mode=WAL` returns the new mode as a row.
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::Other("failed to enable WAL mode"));
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // `STRICT` and `WITHOUT ROWID` flags are per-table, not pragmas.

        let mut store = Self { conn };
        store.run_migrations()?;
        Ok(store)
    }

    /// Apply any unapplied migrations.
    fn run_migrations(&mut self) -> Result<()> {
        // Bootstrap the migrations table so the first migration can record
        // itself.  We create it idempotently here too in case the very
        // first migration script is replaced in the future.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (\
                version INTEGER PRIMARY KEY,\
                applied_at TEXT NOT NULL\
            ) STRICT;",
        )?;

        for &(version, name, sql) in MIGRATIONS {
            let exists: Option<u32> = self
                .conn
                .query_row(
                    "SELECT version FROM schema_migrations WHERE version = ?1",
                    params![version],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_some() {
                continue;
            }

            let tx = self.conn.transaction()?;
            tx.execute_batch(sql).map_err(|e| {
                let _ = name; // suppress unused-warning chain
                Error::Storage(e)
            })?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![version, chrono::Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
            tracing::info!(version, name, "applied migration");
        }
        Ok(())
    }

    /// Borrow the underlying connection (for tests / advanced queries).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    // --- meta -------------------------------------------------------

    /// Read the singleton `meta` row, if present.
    pub fn get_meta(&self) -> Result<Option<MetaRow>> {
        let row = self
            .conn
            .query_row(
                "SELECT format_version, salt, kdf_phc, wrap_nonce, wrap_aead, \
                        monotonic_counter, created_at, \
                        recovery_format, recovery_wrap_nonce, recovery_wrap_aead \
                 FROM meta WHERE id = 1",
                [],
                |r| {
                    let salt_v: Vec<u8> = r.get(1)?;
                    let nonce_v: Vec<u8> = r.get(3)?;
                    Ok((
                        r.get::<_, i64>(0)? as u32,
                        salt_v,
                        r.get::<_, String>(2)?,
                        nonce_v,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, i64>(5)? as u64,
                        r.get::<_, String>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, Option<Vec<u8>>>(8)?,
                        r.get::<_, Option<Vec<u8>>>(9)?,
                    ))
                },
            )
            .optional()?;
        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        if row.1.len() != 16 {
            return Err(Error::VaultFormat("meta.salt wrong length"));
        }
        if row.3.len() != 24 {
            return Err(Error::VaultFormat("meta.wrap_nonce wrong length"));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&row.1);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&row.3);
        let recovery_wrap_nonce = match row.8 {
            Some(v) => {
                if v.len() != 24 {
                    return Err(Error::VaultFormat("meta.recovery_wrap_nonce wrong length"));
                }
                let mut n = [0u8; 24];
                n.copy_from_slice(&v);
                Some(n)
            }
            None => None,
        };
        Ok(Some(MetaRow {
            format_version: row.0,
            salt,
            kdf_phc: row.2,
            wrap_nonce: nonce,
            wrap_aead: row.4,
            monotonic_counter: row.5,
            created_at: row.6,
            recovery_format: row.7,
            recovery_wrap_nonce,
            recovery_wrap_aead: row.9,
        }))
    }

    /// Insert the singleton `meta` row. Errors if it already exists.
    pub fn set_meta(&self, m: &MetaRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (id, format_version, salt, kdf_phc, wrap_nonce, \
                wrap_aead, monotonic_counter, created_at, \
                recovery_format, recovery_wrap_nonce, recovery_wrap_aead) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                m.format_version as i64,
                &m.salt[..],
                &m.kdf_phc,
                &m.wrap_nonce[..],
                &m.wrap_aead,
                m.monotonic_counter as i64,
                &m.created_at,
                &m.recovery_format,
                m.recovery_wrap_nonce.as_ref().map(|n| n.to_vec()),
                &m.recovery_wrap_aead,
            ],
        )?;
        Ok(())
    }

    /// Replace the passphrase-wrap fields (`wrap_nonce`, `wrap_aead`,
    /// `salt`, `kdf_phc`) on the singleton meta row. Used by
    /// `cloak restore` after re-wrapping the master key under a new
    /// passphrase. The recovery wrap is left intact.
    pub fn update_passphrase_wrap(
        &self,
        salt: &[u8; 16],
        kdf_phc: &str,
        wrap_nonce: &[u8; 24],
        wrap_aead: &[u8],
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE meta \
             SET salt = ?1, kdf_phc = ?2, wrap_nonce = ?3, wrap_aead = ?4 \
             WHERE id = 1",
            params![&salt[..], kdf_phc, &wrap_nonce[..], wrap_aead],
        )?;
        if n != 1 {
            return Err(Error::VaultFormat("meta missing"));
        }
        Ok(())
    }

    /// Bump the monotonic counter to `new_value`. Refuses to roll back —
    /// `new_value` must be strictly greater than the current value.
    pub fn bump_counter(&self, new_value: u64) -> Result<()> {
        let current: Option<i64> = self
            .conn
            .query_row("SELECT monotonic_counter FROM meta WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        let current = current.ok_or(Error::VaultFormat("meta missing"))? as u64;
        if new_value <= current {
            return Err(Error::VaultRollbackDetected);
        }
        self.conn.execute(
            "UPDATE meta SET monotonic_counter = ?1 WHERE id = 1",
            params![new_value as i64],
        )?;
        Ok(())
    }

    // --- secrets ---------------------------------------------------

    /// Insert a new secret row. Returns the assigned rowid.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_secret(
        &self,
        name: &str,
        kind: &str,
        tags_json: &str,
        created_at: &str,
        updated_at: &str,
        version: u64,
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<i64> {
        match self.conn.execute(
            "INSERT INTO secrets (name, kind, tags, created_at, updated_at, \
                version, nonce, ciphertext) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                name,
                kind,
                tags_json,
                created_at,
                updated_at,
                version as i64,
                &nonce[..],
                ciphertext,
            ],
        ) {
            Ok(_) => Ok(self.conn.last_insert_rowid()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(Error::SecretExists(name.to_string()))
            }
            Err(e) => Err(Error::Storage(e)),
        }
    }

    /// Update an existing secret's value. The caller is responsible for
    /// re-encrypting; we just persist `(updated_at, version, nonce, ciphertext)`.
    pub fn update_secret_value(
        &self,
        name: &str,
        updated_at: &str,
        version: u64,
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE secrets \
             SET updated_at = ?1, version = ?2, nonce = ?3, ciphertext = ?4 \
             WHERE name = ?5",
            params![updated_at, version as i64, &nonce[..], ciphertext, name],
        )?;
        if n == 0 {
            return Err(Error::SecretNotFound(name.to_string()));
        }
        Ok(())
    }

    /// Delete a secret by name.
    pub fn delete_secret(&self, name: &str) -> Result<()> {
        let n = self
            .conn
            .execute("DELETE FROM secrets WHERE name = ?1", params![name])?;
        if n == 0 {
            return Err(Error::SecretNotFound(name.to_string()));
        }
        Ok(())
    }

    /// List metadata for all secrets, ordered by name.
    pub fn list_secrets(&self) -> Result<Vec<SecretRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, kind, tags, created_at, updated_at, version, nonce, ciphertext \
             FROM secrets ORDER BY name",
        )?;
        let iter = stmt.query_map([], row_to_secret)?;
        let mut out = Vec::new();
        for r in iter {
            out.push(r?);
        }
        Ok(out)
    }

    /// Fetch a single secret row by name.
    pub fn get_secret_row(&self, name: &str) -> Result<SecretRow> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, kind, tags, created_at, updated_at, version, nonce, ciphertext \
                 FROM secrets WHERE name = ?1",
                params![name],
                row_to_secret,
            )
            .optional()?;
        row.ok_or_else(|| Error::SecretNotFound(name.to_string()))
    }

    /// Total number of stored secrets.
    pub fn count_secrets(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?;
        Ok(n as u64)
    }
}

fn row_to_secret(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRow> {
    let nonce_v: Vec<u8> = r.get(7)?;
    let mut nonce = [0u8; 24];
    if nonce_v.len() == 24 {
        nonce.copy_from_slice(&nonce_v);
    } else {
        return Err(rusqlite::Error::InvalidColumnType(
            7,
            "nonce".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    Ok(SecretRow {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        tags_json: r.get(3)?,
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
        version: r.get::<_, i64>(6)? as u64,
        nonce,
        ciphertext: r.get(8)?,
    })
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, SqliteStore) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cloak");
        let s = SqliteStore::open(&path).unwrap();
        (dir, s)
    }

    #[test]
    fn opens_in_wal_mode() {
        let (_d, s) = fresh_store();
        let mode: String = s
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert!(mode.eq_ignore_ascii_case("wal"), "got {mode}");
    }

    #[test]
    fn migration_recorded() {
        let (_d, s) = fresh_store();
        let n: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn migration_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let _ = SqliteStore::open(&path).unwrap();
        let _ = SqliteStore::open(&path).unwrap();
        let s = SqliteStore::open(&path).unwrap();
        let n: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        // One row per applied migration; bump as new migrations land.
        assert_eq!(n, MIGRATIONS.len() as i64);
    }

    #[test]
    fn strict_mode_rejects_text_in_int_column() {
        let (_d, s) = fresh_store();
        // monotonic_counter is INTEGER under STRICT — inserting a string
        // value should fail.
        let r = s.conn.execute(
            "INSERT INTO meta (id, format_version, salt, kdf_phc, wrap_nonce, \
                wrap_aead, monotonic_counter, created_at, \
                recovery_format, recovery_wrap_nonce, recovery_wrap_aead) \
             VALUES (1, 1, x'00000000000000000000000000000000', '', \
                x'000000000000000000000000000000000000000000000000', x'', \
                'not-a-number', '2025-01-01T00:00:00Z', NULL, NULL, NULL)",
            [],
        );
        assert!(r.is_err(), "STRICT should reject text in INTEGER column");
    }

    #[test]
    fn meta_roundtrip_and_counter_rollback() {
        let (_d, s) = fresh_store();
        let m = MetaRow {
            format_version: 1,
            salt: [1u8; 16],
            kdf_phc: "$argon2id$v=19$m=1,t=1,p=1$AAAA".into(),
            wrap_nonce: [2u8; 24],
            wrap_aead: vec![3u8; 48],
            monotonic_counter: 1,
            created_at: "2025-01-01T00:00:00Z".into(),
            recovery_format: None,
            recovery_wrap_nonce: None,
            recovery_wrap_aead: None,
        };
        s.set_meta(&m).unwrap();
        let r = s.get_meta().unwrap().unwrap();
        assert_eq!(r.format_version, 1);
        assert_eq!(r.salt, [1u8; 16]);
        assert_eq!(r.monotonic_counter, 1);

        // Forward bump succeeds.
        s.bump_counter(2).unwrap();
        // Equal value rejected.
        assert!(matches!(
            s.bump_counter(2),
            Err(Error::VaultRollbackDetected)
        ));
        // Lower value rejected.
        assert!(matches!(
            s.bump_counter(1),
            Err(Error::VaultRollbackDetected)
        ));
        // Forward again works.
        s.bump_counter(3).unwrap();
        assert_eq!(s.get_meta().unwrap().unwrap().monotonic_counter, 3);
    }

    #[test]
    fn secret_crud_basic() {
        let (_d, s) = fresh_store();
        let nonce = [0u8; 24];
        s.insert_secret(
            "alpha",
            "api_key",
            "[]",
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            1,
            &nonce,
            b"ciphertext-bytes",
        )
        .unwrap();
        // Duplicate name → typed error.
        let dup = s.insert_secret(
            "alpha",
            "api_key",
            "[]",
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            1,
            &nonce,
            b"ciphertext-bytes",
        );
        assert!(matches!(dup, Err(Error::SecretExists(_))));

        let row = s.get_secret_row("alpha").unwrap();
        assert_eq!(row.name, "alpha");
        assert_eq!(row.ciphertext, b"ciphertext-bytes");

        s.update_secret_value("alpha", "2025-01-02T00:00:00Z", 2, &nonce, b"new-ct")
            .unwrap();
        let row = s.get_secret_row("alpha").unwrap();
        assert_eq!(row.version, 2);
        assert_eq!(row.ciphertext, b"new-ct");

        s.delete_secret("alpha").unwrap();
        assert!(matches!(
            s.get_secret_row("alpha"),
            Err(Error::SecretNotFound(_))
        ));
        assert!(matches!(
            s.delete_secret("alpha"),
            Err(Error::SecretNotFound(_))
        ));
    }
}
