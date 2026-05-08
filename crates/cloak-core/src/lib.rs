//! Cloak core library — vault, crypto, daemon, IPC.
//!
//! Security boundary: this crate is the **only** code in the workspace that
//! handles raw secret material. The MCP shim never sees plaintext.
//!
//! # Invariants
//! - All AEAD goes through [`crypto::aead`] (XChaCha20-Poly1305-IETF only).
//! - All KDF goes through [`crypto::kdf`] (Argon2id keyed mode only).
//! - Secret-typed values use [`crypto::Secret`] (zeroize-on-drop).
//! - Outbound HTTP originates here ([`egress`]) — never in `cloak-mcp`.

// NOTE: We cannot use `#![forbid(unsafe_code)]` here because `crypto.rs`
// must call libsodium FFI directly. Instead we lock down unsafe usage by
// requiring every unsafe operation to live inside an explicit `unsafe { ... }`
// block (even inside `unsafe fn`s) and document the invariant via SAFETY:
// comments. All `unsafe` is confined to `crypto::*`.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod audit;
pub mod biometric;
pub mod crypto;
pub mod egress;
pub mod error;
pub mod handlers;
pub mod ipc;
pub mod keychain;
pub mod policy;
pub mod recovery;
pub mod store;
pub mod vault;

#[cfg(unix)]
pub mod daemon;
#[cfg(unix)]
pub mod peer_auth;
#[cfg(unix)]
pub mod session;

pub use error::{Error, Result};

/// Crate version, propagated to CLI/MCP for `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
