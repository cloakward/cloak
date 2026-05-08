//! Typed errors used across the cloak-core crate.

use thiserror::Error;

/// Result alias for cloak-core operations.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors from cloak-core. Error messages never contain secret material.
#[derive(Debug, Error)]
pub enum Error {
    /// AEAD seal/open failed — typically a tampered ciphertext or wrong key.
    #[error("aead: {0}")]
    Aead(&'static str),

    /// KDF derivation failed (libsodium returned non-zero).
    #[error("kdf: {0}")]
    Kdf(&'static str),

    /// libsodium initialization failure.
    #[error("sodium init failed")]
    SodiumInit,

    /// Vault format / decode error.
    #[error("vault format: {0}")]
    VaultFormat(&'static str),

    /// Unsupported vault version.
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u32),

    /// Vault rollback detected via monotonic counter.
    #[error("vault rollback detected (counter went backwards)")]
    VaultRollbackDetected,

    /// Wrong passphrase or corrupted master key wrapper.
    #[error("invalid passphrase or tampered vault")]
    InvalidPassphrase,

    /// Recovery mnemonic failed to parse / validate, OR the recovery
    /// wrap could not be opened with the supplied mnemonic.
    #[error("invalid recovery mnemonic")]
    InvalidMnemonic,

    /// The vault was created before the BIP-39 recovery seed feature
    /// shipped and therefore has no recovery wrap to use.
    #[error("this vault has no recovery seed (created before recovery seed support landed; create a new vault to opt in — migration in v1.1)")]
    NoRecoveryWrap,

    /// Record with the given name already exists.
    #[error("secret already exists: {0}")]
    SecretExists(String),

    /// Record not found.
    #[error("secret not found: {0}")]
    SecretNotFound(String),

    /// Keychain / Secret Service / DPAPI access failure.
    #[error("keychain: {0}")]
    Keychain(String),

    /// SQLite I/O.
    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),

    /// Filesystem I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    /// Peer authentication failure.
    #[error("peer not trusted")]
    PeerNotTrusted,

    /// Session token unknown / expired / revoked.
    #[error("session not found or expired")]
    SessionExpired,

    /// IPC framing error (oversize, malformed, truncated).
    #[error("ipc framing: {0}")]
    IpcFraming(&'static str),

    /// Policy denied the operation.
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// Confirmation timed out or was rejected.
    #[error("confirmation rejected")]
    ConfirmationRejected,

    /// Server-side biometric / user-presence prompt was cancelled,
    /// timed out, unavailable, or otherwise not confirmed. Returned by
    /// the daemon's `vault.show` handler before any plaintext is
    /// produced — a same-UID attacker who connects to the daemon
    /// socket directly cannot bypass this.
    #[error("biometric / user-presence not confirmed")]
    BiometricFailed,

    /// Audit log integrity check failed.
    #[error("audit chain broken at line {0}")]
    AuditChainBroken(u64),

    /// Generic constraint violation; carries a static message (never secret).
    #[error("{0}")]
    Other(&'static str),
}
