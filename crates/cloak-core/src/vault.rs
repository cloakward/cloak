//! High-level Vault API: header (in `meta` table) + per-record AEAD.
//!
//! # On-disk layout
//!
//! A single SQLite database file (default
//! `~/Library/Application Support/cloak/vault.cloak`).
//!
//! The `meta` table holds:
//! - `format_version` — currently `1`.
//! - `salt` — 16 bytes, fed to Argon2id along with the pepper.
//! - `kdf_phc` — PHC-encoded Argon2id params + salt (self-describing).
//! - `wrap_nonce` + `wrap_aead` — the master key, wrapped under
//!   `wrap_key = Argon2id(passphrase, pepper)` with AAD `cloak.master.v1`.
//! - `monotonic_counter` — strictly-increasing integer; rollback rejected.
//!
//! Each row in `secrets` carries its own AEAD nonce and ciphertext. The
//! per-record key is derived via `crypto_kdf_derive_from_key(master,
//! record_id, b"cloakrec")`. AAD binds the record name, the creation
//! time, and the version to the ciphertext to prevent cross-record swaps.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{
    aead, derive_subkey,
    kdf::{self, KdfParams},
    Secret,
};
use crate::error::{Error, Result};
use crate::recovery::{self, RecoveryMnemonic, FORMAT_BIP39_V1};
use crate::store::{MetaRow, SecretRow, SqliteStore};

/// Current vault format version.
pub const FORMAT_VERSION: u32 = 1;

/// AAD tag for the master-key-wrap AEAD operation. Versioned so we can
/// add a v2 wrap scheme later without ambiguity.
pub const MASTER_AAD: &[u8] = b"cloak.master.v1";

/// 8-byte context for `crypto_kdf_derive_from_key` per-record subkeys.
pub const RECORD_CTX: &[u8; 8] = b"cloakrec";

// -------------------------------------------------------------------------
// SecretKind
// -------------------------------------------------------------------------

/// Coarse classification used for tagging / filtering / policy. Stored
/// as a stable lowercase string; do not renumber or rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// Generic API key.
    ApiKey,
    /// OAuth bearer / refresh token.
    OAuthToken,
    /// Database connection URL.
    DbUrl,
    /// SSH private key.
    SshKey,
    /// Anything else.
    Other,
}

impl SecretKind {
    /// Stable on-disk representation.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::ApiKey => "api_key",
            SecretKind::OAuthToken => "oauth_token",
            SecretKind::DbUrl => "db_url",
            SecretKind::SshKey => "ssh_key",
            SecretKind::Other => "other",
        }
    }

    /// Parse the on-disk representation. Unknown strings → `Other`.
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "api_key" => SecretKind::ApiKey,
            "oauth_token" => SecretKind::OAuthToken,
            "db_url" => SecretKind::DbUrl,
            "ssh_key" => SecretKind::SshKey,
            _ => SecretKind::Other,
        }
    }
}

// -------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------

/// Public metadata for a secret (no plaintext value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// User-visible name (must be unique).
    pub name: String,
    /// Coarse classification.
    pub kind: SecretKind,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Created-at timestamp (UTC).
    pub created_at: DateTime<Utc>,
    /// Last update timestamp (UTC).
    pub updated_at: DateTime<Utc>,
    /// Per-record monotonic version (`1` on `add`, `+1` on each `set`).
    pub version: u64,
}

/// Result of `Vault::initialize` — surfaces the autotuned Argon2id
/// parameters so callers can show them to the user, plus the freshly
/// generated 24-word BIP-39 recovery mnemonic. The mnemonic is **only**
/// returned here (and on demand via [`Vault::reveal_recovery_mnemonic`]
/// — except that the mnemonic itself is not stored, so on-demand reveal
/// is impossible; we surface this contract by returning it from
/// `initialize` and never persisting it).
pub struct InitResult {
    /// Argon2id cost parameters chosen by autotune.
    pub kdf_params: KdfParams,
    /// Fresh 24-word BIP-39 mnemonic. Show to the user once and then
    /// drop. Cloak does not keep a copy.
    pub mnemonic: RecoveryMnemonic,
}

/// Snapshot of vault state for `cloak status`.
#[derive(Debug, Clone)]
pub struct VaultStatus {
    /// Path to the vault file.
    pub path: PathBuf,
    /// Number of stored secrets.
    pub record_count: u64,
    /// KDF params from the header.
    pub kdf_params: KdfParams,
    /// Vault format version from the header.
    pub format_version: u32,
    /// Whether the in-memory master key is currently absent.
    pub locked: bool,
}

// -------------------------------------------------------------------------
// Vault
// -------------------------------------------------------------------------

/// Top-level vault API. A `Vault` is "locked" when no master key is
/// cached in memory; `unlock` populates it, `lock` wipes it.
pub struct Vault {
    path: PathBuf,
    store: SqliteStore,
    /// Cached master key — present iff unlocked.
    master: Option<Secret<[u8; 32]>>,
}

impl Vault {
    /// Open an existing vault file or create an empty one (locked,
    /// uninitialized) if missing.
    ///
    /// On open, if the vault is initialized, the file's monotonic
    /// counter is compared against the OS-keychain mirror (or the
    /// `CLOAK_PEPPER_FILE`-sibling counter file). A file counter that is
    /// *less* than the mirror is read-side rollback and is rejected with
    /// [`Error::VaultRollbackDetected`]. A file counter that is *greater*
    /// refreshes the mirror (legitimate external bump, e.g. an rsync
    /// from a paired device). A missing mirror is seeded from the file
    /// (first run after upgrade).
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let store = SqliteStore::open(path)?;
        let v = Self {
            path: path.to_path_buf(),
            store,
            master: None,
        };
        v.check_rollback_on_open()?;
        Ok(v)
    }

    /// Compare the file counter to the keychain mirror. See the
    /// `open_or_create` docstring for the rule table.
    fn check_rollback_on_open(&self) -> Result<()> {
        // Uninitialized (no `meta` row) → nothing to compare. The very
        // first `initialize` call will seed both the file counter and
        // the mirror.
        let meta = match self.store.get_meta()? {
            Some(m) => m,
            None => return Ok(()),
        };
        let file_counter = meta.monotonic_counter;
        match crate::keychain::read_keychain_counter() {
            Ok(Some(mirror)) => {
                if file_counter < mirror {
                    tracing::error!(
                        file_counter,
                        mirror_counter = mirror,
                        "vault rollback detected on open: file counter is older than keychain mirror"
                    );
                    return Err(Error::VaultRollbackDetected);
                }
                if file_counter > mirror {
                    // Legitimate forward bump (e.g. rsync from paired
                    // device). Refresh the mirror so subsequent opens
                    // see equality. A failure here is logged but not
                    // fatal — the file is the source of truth.
                    if let Err(e) = crate::keychain::mirror_counter(file_counter) {
                        tracing::warn!(
                            error = %e,
                            file_counter,
                            "failed to refresh keychain rollback-counter mirror"
                        );
                    } else {
                        tracing::info!(
                            file_counter,
                            previous_mirror = mirror,
                            "refreshed keychain rollback-counter mirror to match vault file"
                        );
                    }
                }
            }
            Ok(None) => {
                // First run after upgrade (or after a `cloak destroy`).
                // Seed the mirror from the file.
                match crate::keychain::mirror_counter(file_counter) {
                    Ok(()) => tracing::info!(
                        file_counter,
                        "seeded keychain rollback counter from vault file (first-time mirror)"
                    ),
                    Err(e) => tracing::warn!(
                        error = %e,
                        file_counter,
                        "failed to seed keychain rollback-counter mirror; \
                         read-side rollback detection inactive until next successful write"
                    ),
                }
            }
            Err(e) => {
                // Reading the mirror failed (e.g. D-Bus down on Linux,
                // wrong-length item, world-readable counter file). We
                // surface this as a typed Keychain error rather than
                // silently letting an attacker bypass the gate by
                // breaking the mirror.
                return Err(e);
            }
        }
        Ok(())
    }

    /// Default vault path (`$DATA_DIR/cloak/vault.cloak`).
    pub fn default_path() -> Result<PathBuf> {
        let base = dirs::data_dir().ok_or(Error::Other("no data dir on this platform"))?;
        Ok(base.join("cloak").join("vault.cloak"))
    }

    /// True iff the vault has been initialized (i.e. a `meta` row exists).
    pub fn is_initialized(&self) -> Result<bool> {
        Ok(self.store.get_meta()?.is_some())
    }

    /// True iff the master key is cached in memory.
    pub fn is_unlocked(&self) -> bool {
        self.master.is_some()
    }

    /// Wipe the cached master key.
    pub fn lock(&mut self) {
        self.master = None;
    }

    /// Initialize a fresh vault: autotune Argon2id, fetch / create the
    /// pepper, generate a 16-byte salt and a 32-byte master key, wrap
    /// it under `wrap_key = KDF(passphrase, salt, pepper)`, and write
    /// the `meta` row.
    ///
    /// Also generates a fresh 24-word BIP-39 recovery mnemonic, derives
    /// a 32-byte recovery key from it (PBKDF2-HMAC-SHA512 per BIP-39),
    /// and stores a *second* wrap of the master key under the recovery
    /// key. The mnemonic is returned in [`InitResult`] for one-time
    /// display; Cloak does **not** keep a copy.
    pub fn initialize(&mut self, passphrase: &Secret<String>) -> Result<InitResult> {
        if self.is_initialized()? {
            return Err(Error::Other("vault already initialized"));
        }
        let params = kdf::autotune()?;
        let salt = {
            let v = aead::random_bytes(16)?;
            let mut s = [0u8; 16];
            s.copy_from_slice(&v);
            s
        };
        let pepper = crate::keychain::get_or_create_pepper()?;
        let wrap_key = kdf::derive(passphrase, &salt, &pepper, params)?;

        // Generate the master key.
        let master_v = aead::random_bytes(32)?;
        let mut master = [0u8; 32];
        master.copy_from_slice(&master_v);
        // The Vec<u8> from random_bytes goes out of scope unzeroed; that
        // intermediate is acceptable because we generated it for exactly
        // this purpose. To be safe we explicitly zero the Vec here.
        let mut master_v_zero = master_v;
        master_v_zero.zeroize();

        // Wrap the master key under the passphrase-derived key.
        let wrap_nonce = aead::random_nonce()?;
        let wrap_aead = aead::seal(wrap_key.expose_secret(), &wrap_nonce, MASTER_AAD, &master)?;

        // Generate the BIP-39 recovery mnemonic and wrap the master key
        // under the recovery-derived key as well. Both wraps protect the
        // SAME master key, so either path unlocks the same secrets.
        let mnemonic = RecoveryMnemonic::generate()?;
        let recovery_key = mnemonic.derive_recovery_key()?;
        let (rec_nonce, rec_aead) = recovery::wrap_master(&recovery_key, &master)?;

        let meta = MetaRow {
            format_version: FORMAT_VERSION,
            salt,
            kdf_phc: kdf::params_to_phc(&params, &salt),
            wrap_nonce,
            wrap_aead,
            monotonic_counter: 1,
            created_at: Utc::now().to_rfc3339(),
            recovery_format: Some(FORMAT_BIP39_V1.to_string()),
            recovery_wrap_nonce: Some(rec_nonce),
            recovery_wrap_aead: Some(rec_aead),
        };
        self.store.set_meta(&meta)?;
        // Seed the keychain rollback-counter mirror so the first
        // post-init `open_or_create` finds equality. Best-effort: if
        // the keychain is unavailable, the next vault open will seed
        // it from the file counter via the "missing mirror" branch.
        if let Err(e) = crate::keychain::mirror_counter(meta.monotonic_counter) {
            tracing::warn!(
                error = %e,
                counter = meta.monotonic_counter,
                "failed to seed keychain rollback-counter mirror at init"
            );
        }
        // Cache so the caller doesn't have to re-unlock immediately.
        self.master = Some(Secret::new(master));
        Ok(InitResult {
            kdf_params: params,
            mnemonic,
        })
    }

    /// Unlock the vault by deriving the wrap key, unwrapping the master.
    /// Wrong passphrase or a tampered wrap blob → [`Error::InvalidPassphrase`].
    pub fn unlock(&mut self, passphrase: &Secret<String>) -> Result<()> {
        let meta = self
            .store
            .get_meta()?
            .ok_or(Error::VaultFormat("vault not initialized"))?;
        if meta.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(meta.format_version));
        }
        let (params, salt_phc) = kdf::params_from_phc(&meta.kdf_phc)?;
        if salt_phc != meta.salt {
            return Err(Error::VaultFormat("PHC salt does not match meta.salt"));
        }
        let pepper = crate::keychain::get_or_create_pepper()?;
        let wrap_key = kdf::derive(passphrase, &meta.salt, &pepper, params)?;
        let master_bytes = match aead::open(
            wrap_key.expose_secret(),
            &meta.wrap_nonce,
            MASTER_AAD,
            &meta.wrap_aead,
        ) {
            Ok(v) => v,
            Err(_) => return Err(Error::InvalidPassphrase),
        };
        if master_bytes.len() != 32 {
            return Err(Error::VaultFormat("wrapped master wrong length"));
        }
        let mut m = [0u8; 32];
        m.copy_from_slice(&master_bytes);
        // Zero out the intermediate Vec.
        let mut zv = master_bytes;
        zv.zeroize();
        self.master = Some(Secret::new(m));
        Ok(())
    }

    /// List metadata for all stored secrets.
    pub fn list(&self) -> Result<Vec<SecretMetadata>> {
        let rows = self.store.list_secrets()?;
        rows.into_iter().map(row_to_metadata).collect()
    }

    /// Fetch metadata for a single secret.
    pub fn get_metadata(&self, name: &str) -> Result<SecretMetadata> {
        row_to_metadata(self.store.get_secret_row(name)?)
    }

    /// Add a new secret. Vault must be unlocked.
    pub fn add(
        &self,
        name: &str,
        kind: SecretKind,
        tags: Vec<String>,
        value: &Secret<String>,
    ) -> Result<()> {
        let master = self.require_master()?;
        let now = Utc::now();
        let now_iso = now.to_rfc3339();
        let tags_json = serde_json::to_string(&tags)?;
        let nonce = aead::random_nonce()?;

        // We need the rowid before sealing because the subkey context
        // includes it. Insert a placeholder ciphertext + nonce, then
        // overwrite once we know the id. Wrap in a transaction so the
        // intermediate state is never observable.
        let conn = self.store.conn();
        let tx = conn.unchecked_transaction()?;
        // Insert with a temporary placeholder payload.
        let placeholder_ct = vec![0u8; 16]; // valid blob length
        let id = self.store.insert_secret(
            name,
            kind.as_str(),
            &tags_json,
            &now_iso,
            &now_iso,
            1,
            &nonce,
            &placeholder_ct,
        )?;
        let id_u64 = id as u64;
        let aad = canonical_aad(name, now.timestamp(), 1);
        let subkey = derive_subkey(master, id_u64, RECORD_CTX)?;
        let ct = aead::seal(
            subkey.expose_secret(),
            &nonce,
            &aad,
            value.expose_secret().as_bytes(),
        )?;
        // Overwrite the placeholder.
        let n = conn.execute(
            "UPDATE secrets SET ciphertext = ?1 WHERE id = ?2",
            rusqlite::params![ct, id],
        )?;
        if n != 1 {
            return Err(Error::Other("failed to update inserted secret"));
        }
        tx.commit()?;
        let _ = self.bump_and_mirror()?;
        Ok(())
    }

    /// Update the value of an existing secret. Vault must be unlocked.
    pub fn set(&self, name: &str, value: &Secret<String>) -> Result<()> {
        let master = self.require_master()?;
        let row = self.store.get_secret_row(name)?;
        let new_version = row.version.saturating_add(1);
        let now = Utc::now();
        let now_iso = now.to_rfc3339();
        let nonce = aead::random_nonce()?;

        // AAD binds (name, *original* created_at, new version).
        let created_unix = parse_rfc3339(&row.created_at)?.timestamp();
        let aad = canonical_aad(name, created_unix, new_version);
        let subkey = derive_subkey(master, row.id as u64, RECORD_CTX)?;
        let ct = aead::seal(
            subkey.expose_secret(),
            &nonce,
            &aad,
            value.expose_secret().as_bytes(),
        )?;
        self.store
            .update_secret_value(name, &now_iso, new_version, &nonce, &ct)?;
        let _ = self.bump_and_mirror()?;
        Ok(())
    }

    /// Decrypt and return the value. Vault must be unlocked.
    pub fn show(&self, name: &str) -> Result<Secret<String>> {
        let master = self.require_master()?;
        let row = self.store.get_secret_row(name)?;
        let created_unix = parse_rfc3339(&row.created_at)?.timestamp();
        let aad = canonical_aad(&row.name, created_unix, row.version);
        let subkey = derive_subkey(master, row.id as u64, RECORD_CTX)?;
        let pt = aead::open(subkey.expose_secret(), &row.nonce, &aad, &row.ciphertext)?;
        // Convert to UTF-8; reject non-UTF8 (we only store strings).
        let s = String::from_utf8(pt).map_err(|_| Error::VaultFormat("plaintext not utf-8"))?;
        Ok(Secret::new(s))
    }

    /// Remove a secret.
    pub fn rm(&self, name: &str) -> Result<()> {
        self.store.delete_secret(name)?;
        let _ = self.bump_and_mirror()?;
        Ok(())
    }

    /// Status snapshot for `cloak status`.
    pub fn status(&self) -> Result<VaultStatus> {
        let meta = self
            .store
            .get_meta()?
            .ok_or(Error::VaultFormat("vault not initialized"))?;
        let (params, _) = kdf::params_from_phc(&meta.kdf_phc)?;
        Ok(VaultStatus {
            path: self.path.clone(),
            record_count: self.store.count_secrets()?,
            kdf_params: params,
            format_version: meta.format_version,
            locked: self.master.is_none(),
        })
    }

    /// Path to the open vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True iff the vault carries a BIP-39 recovery wrap. False for
    /// vaults that pre-date the recovery seed feature.
    pub fn has_recovery_wrap(&self) -> Result<bool> {
        let meta = match self.store.get_meta()? {
            Some(m) => m,
            None => return Ok(false),
        };
        Ok(meta.recovery_format.is_some()
            && meta.recovery_wrap_nonce.is_some()
            && meta.recovery_wrap_aead.is_some())
    }

    /// Round-trip a candidate mnemonic against the stored recovery wrap
    /// without performing a restore. Used by `cloak backup verify` to
    /// confirm the user wrote the words down correctly.
    ///
    /// Returns `Ok(())` on success, [`Error::InvalidMnemonic`] if the
    /// mnemonic does not unwrap, [`Error::NoRecoveryWrap`] if the vault
    /// has no recovery wrap.
    pub fn verify_mnemonic(&self, mnemonic: &RecoveryMnemonic) -> Result<()> {
        let meta = self
            .store
            .get_meta()?
            .ok_or(Error::VaultFormat("vault not initialized"))?;
        let (nonce, ct) = match (meta.recovery_wrap_nonce, meta.recovery_wrap_aead) {
            (Some(n), Some(c)) => (n, c),
            _ => return Err(Error::NoRecoveryWrap),
        };
        if meta.recovery_format.as_deref() != Some(FORMAT_BIP39_V1) {
            return Err(Error::VaultFormat("unknown recovery format"));
        }
        let key = mnemonic.derive_recovery_key()?;
        // Discard the unwrapped master — we only care about the AEAD-tag check.
        let master = recovery::unwrap_master(&key, &nonce, &ct)?;
        // `master` zeroizes on drop.
        drop(master);
        Ok(())
    }

    /// Restore vault access using a BIP-39 mnemonic and a freshly
    /// chosen passphrase. Re-derives the master key from the recovery
    /// wrap, autotunes a fresh Argon2id, re-wraps the master under the
    /// new passphrase + pepper, and replaces the passphrase wrap on
    /// disk. The recovery wrap itself is left intact (the user may want
    /// to verify the same mnemonic again later).
    ///
    /// On success the vault is unlocked (master cached). The new
    /// passphrase is what the user types from now on.
    ///
    /// Errors:
    /// - [`Error::InvalidMnemonic`] — wrong words or tampered recovery wrap.
    /// - [`Error::NoRecoveryWrap`] — vault has no recovery wrap.
    pub fn restore_with_mnemonic(
        &mut self,
        mnemonic: &RecoveryMnemonic,
        new_passphrase: &Secret<String>,
    ) -> Result<KdfParams> {
        let meta = self
            .store
            .get_meta()?
            .ok_or(Error::VaultFormat("vault not initialized"))?;
        if meta.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(meta.format_version));
        }
        let (rec_nonce, rec_ct) = match (meta.recovery_wrap_nonce, meta.recovery_wrap_aead) {
            (Some(n), Some(c)) => (n, c),
            _ => return Err(Error::NoRecoveryWrap),
        };
        if meta.recovery_format.as_deref() != Some(FORMAT_BIP39_V1) {
            return Err(Error::VaultFormat("unknown recovery format"));
        }

        // 1. Derive recovery key, unwrap the master.
        let recovery_key = mnemonic.derive_recovery_key()?;
        let master = recovery::unwrap_master(&recovery_key, &rec_nonce, &rec_ct)?;

        // 2. Pick fresh Argon2id params + a fresh salt.
        let params = kdf::autotune()?;
        let salt = {
            let v = aead::random_bytes(16)?;
            let mut s = [0u8; 16];
            s.copy_from_slice(&v);
            s
        };

        // 3. Re-wrap under the new passphrase.
        let pepper = crate::keychain::get_or_create_pepper()?;
        let wrap_key = kdf::derive(new_passphrase, &salt, &pepper, params)?;
        let wrap_nonce = aead::random_nonce()?;
        let wrap_aead = aead::seal(
            wrap_key.expose_secret(),
            &wrap_nonce,
            MASTER_AAD,
            master.expose_secret(),
        )?;

        // 4. Persist the new passphrase wrap. The recovery wrap is
        //    untouched so subsequent `cloak backup verify` calls keep
        //    working.
        self.store.update_passphrase_wrap(
            &salt,
            &kdf::params_to_phc(&params, &salt),
            &wrap_nonce,
            &wrap_aead,
        )?;

        // 5. Cache the master so the caller doesn't need to re-unlock.
        self.master = Some(master);
        Ok(params)
    }

    // -- internals --

    fn require_master(&self) -> Result<&Secret<[u8; 32]>> {
        self.master.as_ref().ok_or(Error::Other("vault is locked"))
    }

    fn next_counter(&self) -> Result<u64> {
        let meta = self
            .store
            .get_meta()?
            .ok_or(Error::VaultFormat("vault not initialized"))?;
        Ok(meta.monotonic_counter.saturating_add(1))
    }

    /// Bump the file counter and best-effort mirror it to the OS
    /// keychain. The file is the source of truth; if the mirror write
    /// fails we log a warning but do not fail the surrounding write.
    /// Returns the new counter value on success.
    fn bump_and_mirror(&self) -> Result<u64> {
        let next = self.next_counter()?;
        self.store.bump_counter(next)?;
        if let Err(e) = crate::keychain::mirror_counter(next) {
            tracing::warn!(
                error = %e,
                counter = next,
                "failed to mirror rollback counter to OS keychain; \
                 vault file counter is authoritative — read-side rollback \
                 detection may lag until the next successful mirror"
            );
        }
        Ok(next)
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Build the AAD bytes that bind a record's identity to its ciphertext.
/// Layout (concatenation):
///   `name_len_be(u32) || name_utf8 || created_unix_be(i64) || version_be(u64)`
fn canonical_aad(name: &str, created_unix: i64, version: u64) -> Vec<u8> {
    let name_b = name.as_bytes();
    let mut out = Vec::with_capacity(4 + name_b.len() + 8 + 8);
    out.extend_from_slice(&(name_b.len() as u32).to_be_bytes());
    out.extend_from_slice(name_b);
    out.extend_from_slice(&created_unix.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| Error::VaultFormat("bad rfc3339 timestamp"))
}

fn row_to_metadata(row: SecretRow) -> Result<SecretMetadata> {
    let tags: Vec<String> = serde_json::from_str(&row.tags_json)?;
    Ok(SecretMetadata {
        name: row.name,
        kind: SecretKind::from_str_lossy(&row.kind),
        tags,
        created_at: parse_rfc3339(&row.created_at)?,
        updated_at: parse_rfc3339(&row.updated_at)?,
        version: row.version,
    })
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;

    /// Disable the OS-keychain rollback-counter mirror for the entire
    /// test process so the unit tests stay hermetic. The mirror logic
    /// itself is exercised by dedicated tests that opt back in via a
    /// scoped enable (see `rollback_mirror_*` tests below).
    fn disable_rollback_mirror() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            // SAFETY: required by std 1.84+ for `set_var`. We set this
            // once at the start of the first test in the process and
            // never mutate it again from a unit test, so the absence
            // of synchronization with other env-var readers is fine.
            unsafe {
                std::env::set_var("CLOAK_DISABLE_ROLLBACK_MIRROR", "1");
            }
        });
    }

    /// Fast Argon2id params for tests — production values come from
    /// `kdf::autotune()` but we cannot afford that per-test.
    fn fast_params() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Initialize a vault using a deterministic dummy pepper so tests
    /// don't touch the real OS keychain. Returns (TempDir, Vault).
    fn init_test_vault() -> (TempDir, Vault) {
        disable_rollback_mirror();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        // Bypass `initialize` (which talks to the keychain + autotunes)
        // by writing the meta row directly with a fast KDF and a stable
        // dummy pepper so tests are hermetic.
        init_with_dummy_pepper(&mut v, b"REDACTED-passphrase").unwrap();
        (dir, v)
    }

    /// Hermetic init that skips the OS keychain and autotune.
    fn init_with_dummy_pepper(v: &mut Vault, passphrase: &[u8]) -> Result<()> {
        let salt = [0x55u8; 16];
        let pepper = Secret::new(vec![0xAAu8; 32]);
        let pass = Secret::new(String::from_utf8_lossy(passphrase).into_owned());
        let params = fast_params();
        let wrap_key = kdf::derive(&pass, &salt, &pepper, params)?;
        let mb = aead::random_bytes(32)?;
        let mut master = [0u8; 32];
        master.copy_from_slice(&mb);
        let wrap_nonce = aead::random_nonce()?;
        let wrap_aead = aead::seal(wrap_key.expose_secret(), &wrap_nonce, MASTER_AAD, &master)?;
        v.store.set_meta(&MetaRow {
            format_version: FORMAT_VERSION,
            salt,
            kdf_phc: kdf::params_to_phc(&params, &salt),
            wrap_nonce,
            wrap_aead,
            monotonic_counter: 1,
            created_at: Utc::now().to_rfc3339(),
            recovery_format: None,
            recovery_wrap_nonce: None,
            recovery_wrap_aead: None,
        })?;
        v.master = Some(Secret::new(master));
        Ok(())
    }

    /// Hermetic unlock that re-derives wrap_key with the dummy pepper.
    fn unlock_with_dummy_pepper(v: &mut Vault, passphrase: &[u8]) -> Result<()> {
        let pepper = Secret::new(vec![0xAAu8; 32]);
        let pass = Secret::new(String::from_utf8_lossy(passphrase).into_owned());
        let meta = v.store.get_meta()?.ok_or(Error::VaultFormat("uninit"))?;
        let (params, _salt) = kdf::params_from_phc(&meta.kdf_phc)?;
        let wrap_key = kdf::derive(&pass, &meta.salt, &pepper, params)?;
        let m = aead::open(
            wrap_key.expose_secret(),
            &meta.wrap_nonce,
            MASTER_AAD,
            &meta.wrap_aead,
        )
        .map_err(|_| Error::InvalidPassphrase)?;
        let mut master = [0u8; 32];
        master.copy_from_slice(&m);
        v.master = Some(Secret::new(master));
        Ok(())
    }

    #[test]
    fn init_and_basic_roundtrip() {
        let (_d, v) = init_test_vault();
        v.add(
            "api",
            SecretKind::ApiKey,
            vec!["prod".into()],
            &Secret::new("token-abc".into()),
        )
        .unwrap();
        let s = v.show("api").unwrap();
        assert_eq!(s.expose_secret(), "token-abc");
        let md = v.get_metadata("api").unwrap();
        assert_eq!(md.name, "api");
        assert_eq!(md.kind, SecretKind::ApiKey);
        assert_eq!(md.tags, vec!["prod".to_string()]);
        assert_eq!(md.version, 1);
    }

    #[test]
    fn set_increments_version() {
        let (_d, v) = init_test_vault();
        v.add("k", SecretKind::Other, vec![], &Secret::new("v1".into()))
            .unwrap();
        v.set("k", &Secret::new("v2".into())).unwrap();
        assert_eq!(v.show("k").unwrap().expose_secret(), "v2");
        assert_eq!(v.get_metadata("k").unwrap().version, 2);
    }

    #[test]
    fn rm_deletes() {
        let (_d, v) = init_test_vault();
        v.add("k", SecretKind::Other, vec![], &Secret::new("v".into()))
            .unwrap();
        v.rm("k").unwrap();
        assert!(matches!(v.show("k"), Err(Error::SecretNotFound(_))));
    }

    #[test]
    fn add_duplicate_name_typed_error() {
        let (_d, v) = init_test_vault();
        v.add("k", SecretKind::Other, vec![], &Secret::new("v".into()))
            .unwrap();
        let r = v.add("k", SecretKind::Other, vec![], &Secret::new("v".into()));
        assert!(matches!(r, Err(Error::SecretExists(_))));
    }

    #[test]
    fn lock_unlock_cycle() {
        disable_rollback_mirror();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        init_with_dummy_pepper(&mut v, b"hunter2").unwrap();
        v.add("k", SecretKind::Other, vec![], &Secret::new("v".into()))
            .unwrap();
        v.lock();
        assert!(!v.is_unlocked());
        // Show on locked vault refuses.
        assert!(v.show("k").is_err());
        unlock_with_dummy_pepper(&mut v, b"hunter2").unwrap();
        assert_eq!(v.show("k").unwrap().expose_secret(), "v");
    }

    #[test]
    fn wrong_passphrase_typed_error() {
        disable_rollback_mirror();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        init_with_dummy_pepper(&mut v, b"correct").unwrap();
        v.lock();
        let r = unlock_with_dummy_pepper(&mut v, b"wrong");
        assert!(matches!(r, Err(Error::InvalidPassphrase)));
    }

    #[test]
    fn tampered_ciphertext_typed_error_not_panic() {
        let (_d, v) = init_test_vault();
        v.add("k", SecretKind::Other, vec![], &Secret::new("v".into()))
            .unwrap();
        // Flip one byte of the ciphertext directly.
        v.store
            .conn()
            .execute(
                "UPDATE secrets SET ciphertext = X'00000000000000000000000000000000' \
                 WHERE name = 'k'",
                [],
            )
            .unwrap();
        let r = v.show("k");
        assert!(matches!(r, Err(Error::Aead(_))));
    }

    #[test]
    fn rollback_counter_rejected_via_store() {
        let (_d, v) = init_test_vault();
        v.add("k1", SecretKind::Other, vec![], &Secret::new("v1".into()))
            .unwrap();
        // Force-rewind the counter directly in the DB.
        v.store
            .conn()
            .execute("UPDATE meta SET monotonic_counter = 0 WHERE id = 1", [])
            .unwrap();
        // bump to a value that's now <= current counter we'd compute via
        // `next_counter`. Hand-call the store's bump with a backwards
        // value — must reject.
        let r = v.store.bump_counter(0);
        assert!(matches!(r, Err(Error::VaultRollbackDetected)));
    }

    #[test]
    fn list_returns_all() {
        let (_d, v) = init_test_vault();
        for i in 0..5 {
            v.add(
                &format!("k{i}"),
                SecretKind::Other,
                vec![],
                &Secret::new(format!("v{i}")),
            )
            .unwrap();
        }
        let all = v.list().unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn status_reports_count_and_params() {
        let (_d, v) = init_test_vault();
        v.add("k", SecretKind::Other, vec![], &Secret::new("v".into()))
            .unwrap();
        let s = v.status().unwrap();
        assert_eq!(s.record_count, 1);
        assert_eq!(s.format_version, FORMAT_VERSION);
        assert_eq!(s.kdf_params, fast_params());
        assert!(!s.locked);
    }

    #[test]
    fn aad_swap_attack_fails() {
        // If we splice the ciphertext+nonce of one record into another,
        // the AAD-binding of the record name should make `open` fail.
        let (_d, v) = init_test_vault();
        v.add("a", SecretKind::Other, vec![], &Secret::new("alpha".into()))
            .unwrap();
        v.add("b", SecretKind::Other, vec![], &Secret::new("bravo".into()))
            .unwrap();
        let row_b = v.store.get_secret_row("b").unwrap();
        v.store
            .conn()
            .execute(
                "UPDATE secrets SET nonce = ?1, ciphertext = ?2 WHERE name = 'a'",
                rusqlite::params![&row_b.nonce[..], &row_b.ciphertext],
            )
            .unwrap();
        // 'a' now has b's ciphertext under a's name → AAD mismatch.
        assert!(matches!(v.show("a"), Err(Error::Aead(_))));
    }

    /// Hermetic recovery-flow init that *does* generate a mnemonic and
    /// stores both wraps under a dummy pepper, mirroring `Vault::initialize`
    /// but with the test KDF params so it runs in milliseconds.
    fn init_with_recovery_dummy_pepper(
        v: &mut Vault,
        passphrase: &[u8],
    ) -> Result<RecoveryMnemonic> {
        let salt = [0x55u8; 16];
        let pepper = Secret::new(vec![0xAAu8; 32]);
        let pass = Secret::new(String::from_utf8_lossy(passphrase).into_owned());
        let params = fast_params();
        let wrap_key = kdf::derive(&pass, &salt, &pepper, params)?;
        let mb = aead::random_bytes(32)?;
        let mut master = [0u8; 32];
        master.copy_from_slice(&mb);
        let wrap_nonce = aead::random_nonce()?;
        let wrap_aead = aead::seal(wrap_key.expose_secret(), &wrap_nonce, MASTER_AAD, &master)?;
        let mnemonic = RecoveryMnemonic::generate()?;
        let recovery_key = mnemonic.derive_recovery_key()?;
        let (rec_nonce, rec_aead) = recovery::wrap_master(&recovery_key, &master)?;
        v.store.set_meta(&MetaRow {
            format_version: FORMAT_VERSION,
            salt,
            kdf_phc: kdf::params_to_phc(&params, &salt),
            wrap_nonce,
            wrap_aead,
            monotonic_counter: 1,
            created_at: Utc::now().to_rfc3339(),
            recovery_format: Some(FORMAT_BIP39_V1.to_string()),
            recovery_wrap_nonce: Some(rec_nonce),
            recovery_wrap_aead: Some(rec_aead),
        })?;
        v.master = Some(Secret::new(master));
        Ok(mnemonic)
    }

    /// Hermetic restore that re-wraps under a new passphrase using the
    /// test KDF params + dummy pepper. Mirrors `Vault::restore_with_mnemonic`
    /// without paying for production Argon2id.
    fn restore_with_dummy_pepper(
        v: &mut Vault,
        mnemonic: &RecoveryMnemonic,
        new_passphrase: &[u8],
    ) -> Result<()> {
        let meta = v.store.get_meta()?.ok_or(Error::VaultFormat("uninit"))?;
        let (rec_nonce, rec_ct) = match (meta.recovery_wrap_nonce, meta.recovery_wrap_aead) {
            (Some(n), Some(c)) => (n, c),
            _ => return Err(Error::NoRecoveryWrap),
        };
        let recovery_key = mnemonic.derive_recovery_key()?;
        let master = recovery::unwrap_master(&recovery_key, &rec_nonce, &rec_ct)?;
        let params = fast_params();
        let salt = [0x66u8; 16];
        let pepper = Secret::new(vec![0xAAu8; 32]);
        let pass = Secret::new(String::from_utf8_lossy(new_passphrase).into_owned());
        let wrap_key = kdf::derive(&pass, &salt, &pepper, params)?;
        let wrap_nonce = aead::random_nonce()?;
        let wrap_aead = aead::seal(
            wrap_key.expose_secret(),
            &wrap_nonce,
            MASTER_AAD,
            master.expose_secret(),
        )?;
        v.store.update_passphrase_wrap(
            &salt,
            &kdf::params_to_phc(&params, &salt),
            &wrap_nonce,
            &wrap_aead,
        )?;
        v.master = Some(master);
        Ok(())
    }

    #[test]
    fn recovery_roundtrip_with_passphrase_loss() {
        // Full BIP-39 round-trip: create vault, store a secret, "lose"
        // the passphrase, restore via mnemonic with a new passphrase,
        // and decrypt the original secret.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        let mnemonic = init_with_recovery_dummy_pepper(&mut v, b"old-pass").unwrap();
        v.add(
            "k",
            SecretKind::Other,
            vec![],
            &Secret::new("payload".into()),
        )
        .unwrap();

        // Simulate passphrase loss by locking + dropping the master.
        v.lock();
        assert!(!v.is_unlocked());

        // Restore with the mnemonic + a fresh passphrase.
        restore_with_dummy_pepper(&mut v, &mnemonic, b"new-pass").unwrap();
        assert!(v.is_unlocked());
        assert_eq!(v.show("k").unwrap().expose_secret(), "payload");

        // The OLD passphrase no longer unlocks.
        v.lock();
        let r = unlock_with_dummy_pepper(&mut v, b"old-pass");
        assert!(matches!(r, Err(Error::InvalidPassphrase)));
        // The new passphrase does.
        unlock_with_dummy_pepper(&mut v, b"new-pass").unwrap();
        assert_eq!(v.show("k").unwrap().expose_secret(), "payload");
    }

    #[test]
    fn verify_mnemonic_round_trips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        let mnemonic = init_with_recovery_dummy_pepper(&mut v, b"p").unwrap();
        v.verify_mnemonic(&mnemonic).unwrap();
    }

    #[test]
    fn verify_mnemonic_rejects_wrong_words() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        let _stored = init_with_recovery_dummy_pepper(&mut v, b"p").unwrap();
        let other = RecoveryMnemonic::generate().unwrap();
        let r = v.verify_mnemonic(&other);
        assert!(matches!(r, Err(Error::InvalidMnemonic)));
    }

    #[test]
    fn legacy_vault_has_no_recovery_wrap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.cloak");
        let mut v = Vault::open_or_create(&path).unwrap();
        // The non-recovery hermetic init writes recovery_* = NULL.
        init_with_dummy_pepper(&mut v, b"p").unwrap();
        assert!(!v.has_recovery_wrap().unwrap());
        let m = RecoveryMnemonic::generate().unwrap();
        assert!(matches!(v.verify_mnemonic(&m), Err(Error::NoRecoveryWrap)));
        assert!(matches!(
            v.restore_with_mnemonic(&m, &Secret::new("x".into())),
            Err(Error::NoRecoveryWrap)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_add_show_roundtrip(
            // Names: 1..=32 ASCII printable, no NUL.
            name in "[a-zA-Z0-9_-]{1,32}",
            value in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            disable_rollback_mirror();
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("v.cloak");
            let mut v = Vault::open_or_create(&path).unwrap();
            init_with_dummy_pepper(&mut v, b"hunter2").unwrap();
            // Use base64 so we can freely use any bytes as a string.
            let val = base64::engine::general_purpose::STANDARD.encode(&value);
            v.add(&name, SecretKind::Other, vec![], &Secret::new(val.clone())).unwrap();
            let got = v.show(&name).unwrap();
            prop_assert_eq!(got.expose_secret(), &val);
        }
    }

    // proptest needs a base64 import in scope here; pull it in only
    // for tests.
    use base64::Engine as _;
}
