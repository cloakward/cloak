//! Session token issuance, validation, and revocation.
//!
//! A session is bound to:
//! - the peer's PID (recorded for audit / debugging),
//! - the peer's binary basename (cheap policy hint for handlers),
//! - an opaque per-connection ID (so a token issued on one socket
//!   cannot be replayed on another).
//!
//! Tokens are 32 random bytes, base64url-encoded (`subtle::ConstantTimeEq`
//! is used for comparison). Default TTL is 30 minutes.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::crypto::aead;
use crate::error::{Error, Result};
use crate::peer_auth::PeerInfo;

/// Default lifetime of a freshly issued session token.
pub fn default_ttl() -> Duration {
    Duration::minutes(30)
}

/// Opaque, random session token.
#[derive(Debug, Clone)]
pub struct SessionToken(pub String);

impl SessionToken {
    /// Generate a fresh token (32 random bytes, base64url encoded).
    pub fn generate() -> Result<Self> {
        let bytes = aead::random_bytes(32)?;
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        Ok(Self(s))
    }

    /// Borrow as a `&str` for transport.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Server-side record for a live session.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Token string (same value the peer sends back over the wire).
    pub token: SessionToken,
    /// Peer PID at the time of issuance (recorded for audit).
    pub peer_pid: i32,
    /// Peer binary basename — used by handlers to route CLI vs MCP.
    pub peer_basename: String,
    /// Unique per-connection ID assigned by the daemon.
    pub conn_id: u64,
    /// UTC timestamp at issuance.
    pub issued_at: DateTime<Utc>,
    /// UTC expiry time (issued_at + ttl).
    pub expires_at: DateTime<Utc>,
}

impl SessionRecord {
    /// True iff `now` is at-or-past `expires_at`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// In-memory store of live sessions, behind a `tokio::sync::RwLock`.
#[derive(Default)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, SessionRecord>>>,
}

impl SessionStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new session token bound to `peer` and `conn_id`.
    pub async fn issue(
        &self,
        peer: &PeerInfo,
        conn_id: u64,
        ttl: Duration,
    ) -> Result<SessionToken> {
        let token = SessionToken::generate()?;
        let now = Utc::now();
        let basename = peer.basename().unwrap_or_default();
        let record = SessionRecord {
            token: token.clone(),
            peer_pid: peer.pid,
            peer_basename: basename,
            conn_id,
            issued_at: now,
            expires_at: now + ttl,
        };
        let mut g = self.inner.write().await;
        g.insert(token.0.clone(), record);
        Ok(token)
    }

    /// Validate `token` against the live set. The token must:
    /// - exist,
    /// - not be expired,
    /// - be bound to `conn_id`.
    ///
    /// The membership lookup uses a constant-time compare against every
    /// candidate to avoid leaking presence by timing on mismatched
    /// lengths. (For modest session counts this is plenty fast; if it
    /// ever isn't, we'll switch to a length-bucketed map.)
    pub async fn validate(&self, token: &str, conn_id: u64) -> Result<SessionRecord> {
        let g = self.inner.read().await;
        let now = Utc::now();
        // Iterate the map and constant-time compare every candidate.
        let mut hit: Option<SessionRecord> = None;
        for (k, v) in g.iter() {
            // ConstantTimeEq.ct_eq returns 1 iff equal. We always
            // perform the compare even after we've matched, to make
            // the loop's timing independent of position.
            let eq: bool = k.as_bytes().ct_eq(token.as_bytes()).into();
            if eq && hit.is_none() {
                hit = Some(v.clone());
            }
        }
        let rec = hit.ok_or(Error::SessionExpired)?;
        if rec.is_expired(now) {
            // Drop the stale entry.
            drop(g);
            self.revoke(token).await;
            return Err(Error::SessionExpired);
        }
        if rec.conn_id != conn_id {
            return Err(Error::SessionExpired);
        }
        Ok(rec)
    }

    /// Revoke a single token. No-op if the token does not exist.
    pub async fn revoke(&self, token: &str) {
        let mut g = self.inner.write().await;
        g.remove(token);
    }

    /// Revoke every session attached to `conn_id` (called on disconnect
    /// or task panic).
    pub async fn revoke_by_conn(&self, conn_id: u64) {
        let mut g = self.inner.write().await;
        g.retain(|_, v| v.conn_id != conn_id);
    }

    /// Drop every expired record. Cheap to call periodically.
    pub async fn purge_expired(&self) {
        let mut g = self.inner.write().await;
        let now = Utc::now();
        g.retain(|_, v| !v.is_expired(now));
    }

    /// Number of live sessions (test helper).
    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_auth::PeerInfo;
    use std::path::PathBuf;

    fn mk_peer(pid: i32, basename: &str) -> PeerInfo {
        PeerInfo {
            pid,
            uid: 501,
            gid: 501,
            binary_path: Some(PathBuf::from(format!("/usr/local/bin/{basename}"))),
            code_sig_hash: Some([0u8; 32]),
        }
    }

    #[tokio::test]
    async fn issue_and_validate_roundtrip() {
        let s = SessionStore::new();
        let p = mk_peer(99, "cloak");
        let tok = s.issue(&p, 7, Duration::minutes(30)).await.unwrap();
        let rec = s.validate(tok.as_str(), 7).await.unwrap();
        assert_eq!(rec.peer_pid, 99);
        assert_eq!(rec.peer_basename, "cloak");
        assert_eq!(rec.conn_id, 7);
    }

    #[tokio::test]
    async fn wrong_conn_id_rejected() {
        let s = SessionStore::new();
        let p = mk_peer(1, "cloak");
        let tok = s.issue(&p, 1, Duration::minutes(30)).await.unwrap();
        assert!(matches!(
            s.validate(tok.as_str(), 2).await,
            Err(Error::SessionExpired)
        ));
    }

    #[tokio::test]
    async fn unknown_token_rejected() {
        let s = SessionStore::new();
        assert!(matches!(
            s.validate("not-a-real-token", 0).await,
            Err(Error::SessionExpired)
        ));
    }

    #[tokio::test]
    async fn expired_token_rejected_and_purged() {
        let s = SessionStore::new();
        let p = mk_peer(1, "cloak");
        // Issue with a TTL of -1s (already expired).
        let tok = s.issue(&p, 1, Duration::seconds(-1)).await.unwrap();
        assert!(matches!(
            s.validate(tok.as_str(), 1).await,
            Err(Error::SessionExpired)
        ));
        // The validate path should have cleaned up the expired record.
        assert_eq!(s.len().await, 0);
    }

    #[tokio::test]
    async fn revoke_invalidates() {
        let s = SessionStore::new();
        let p = mk_peer(1, "cloak");
        let tok = s.issue(&p, 1, Duration::minutes(30)).await.unwrap();
        s.revoke(tok.as_str()).await;
        assert!(matches!(
            s.validate(tok.as_str(), 1).await,
            Err(Error::SessionExpired)
        ));
    }

    #[tokio::test]
    async fn revoke_by_conn_kills_all() {
        let s = SessionStore::new();
        let p = mk_peer(1, "cloak");
        let t1 = s.issue(&p, 5, Duration::minutes(30)).await.unwrap();
        let t2 = s.issue(&p, 5, Duration::minutes(30)).await.unwrap();
        let t3 = s.issue(&p, 6, Duration::minutes(30)).await.unwrap();
        s.revoke_by_conn(5).await;
        assert!(s.validate(t1.as_str(), 5).await.is_err());
        assert!(s.validate(t2.as_str(), 5).await.is_err());
        assert!(s.validate(t3.as_str(), 6).await.is_ok());
    }

    #[tokio::test]
    async fn purge_expired_removes_only_expired() {
        let s = SessionStore::new();
        let p = mk_peer(1, "cloak");
        let _expired = s.issue(&p, 1, Duration::seconds(-1)).await.unwrap();
        let live = s.issue(&p, 1, Duration::minutes(30)).await.unwrap();
        assert_eq!(s.len().await, 2);
        s.purge_expired().await;
        assert_eq!(s.len().await, 1);
        assert!(s.validate(live.as_str(), 1).await.is_ok());
    }

    #[test]
    fn token_is_random_and_long() {
        let a = SessionToken::generate().unwrap();
        let b = SessionToken::generate().unwrap();
        assert_ne!(a.0, b.0);
        // 32 bytes base64url-no-pad → 43 chars.
        assert_eq!(a.0.len(), 43);
    }
}
