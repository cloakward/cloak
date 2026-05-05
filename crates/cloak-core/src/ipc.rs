//! IPC framing (length-prefixed JSON over UDS / Named Pipe).
//!
//! Wire format (frozen — see `docs/IPC_WIRE.md`):
//!
//! ```text
//! +----------------+------------------------------------+
//! | u32 LE length  | UTF-8 JSON body (length bytes)     |
//! +----------------+------------------------------------+
//! ```
//!
//! - Maximum frame size is [`MAX_FRAME_SIZE`] (4 MiB). Anything larger
//!   yields an [`Error::IpcFraming`] and the connection is dropped by
//!   the caller.
//! - Both directions use the same framing.
//! - JSON bodies use the [`Request`] / [`Response`] shapes below.
//!
//! Helpers in this module never log or surface secret material.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};

/// Maximum permitted frame body length, in bytes (4 MiB).
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

// -------------------------------------------------------------------------
// Wire types
// -------------------------------------------------------------------------

/// A single framed message (the JSON body, without the length prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame(pub Vec<u8>);

/// IPC request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Caller-chosen UUID v4. Echoed in the matching response.
    pub id: String,
    /// Dotted method name (e.g. `cli.handshake`, `vault.list`).
    pub method: String,
    /// Method-specific parameters (validated by each handler).
    #[serde(default)]
    pub params: serde_json::Value,
    /// Session token — required for every method except `*.handshake`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// IPC response body. Either `result` or `error` is populated, never both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Mirrors [`Request::id`].
    pub id: String,
    /// Successful result payload (handler-specific shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Failure payload — symbolic code + human message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// Symbolic, lowercase-kebab error returned over the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcError {
    /// Symbolic error code (see `docs/IPC_WIRE.md`).
    pub code: String,
    /// Short human-readable description. Never contains secret material.
    pub message: String,
}

/// Construct an [`RpcError`] from a static code and any message.
pub fn rpc_error(code: &str, msg: impl Into<String>) -> RpcError {
    RpcError {
        code: code.to_string(),
        message: msg.into(),
    }
}

// -------------------------------------------------------------------------
// Mapping our typed `Error` -> wire `RpcError`.
// -------------------------------------------------------------------------

impl Response {
    /// Build a successful response with a JSON result.
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        Self {
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    pub fn err(id: impl Into<String>, error: RpcError) -> Self {
        Self {
            id: id.into(),
            result: None,
            error: Some(error),
        }
    }
}

impl From<&Error> for RpcError {
    fn from(e: &Error) -> Self {
        // Map cloak-core errors to the symbolic codes specified in
        // docs/IPC_WIRE.md. Messages are short, never include secret
        // material, and are safe to surface to the peer.
        match e {
            Error::PeerNotTrusted => rpc_error("peer-not-trusted", "peer not trusted"),
            Error::SessionExpired => rpc_error("session-expired", "session expired"),
            Error::IpcFraming(m) => rpc_error("invalid-params", *m),
            Error::SecretExists(name) => {
                rpc_error("secret-exists", format!("secret already exists: {name}"))
            }
            Error::SecretNotFound(name) => {
                rpc_error("secret-not-found", format!("secret not found: {name}"))
            }
            Error::PolicyDenied(m) => rpc_error("policy-denied", m.clone()),
            Error::ConfirmationRejected => {
                rpc_error("confirmation-rejected", "confirmation rejected")
            }
            Error::AuditChainBroken(line) => {
                rpc_error("audit-broken", format!("audit chain broken at line {line}"))
            }
            Error::Aead(m) => rpc_error("aead-failure", *m),
            Error::Kdf(m) => rpc_error("internal-error", *m),
            Error::SodiumInit => rpc_error("internal-error", "sodium init failed"),
            Error::VaultFormat(m) => rpc_error("internal-error", *m),
            Error::UnsupportedVersion(v) => {
                rpc_error("internal-error", format!("unsupported vault version: {v}"))
            }
            Error::VaultRollbackDetected => rpc_error("internal-error", "vault rollback detected"),
            Error::InvalidPassphrase => {
                rpc_error("invalid-params", "invalid passphrase or tampered vault")
            }
            Error::Keychain(m) => rpc_error("internal-error", format!("keychain: {m}")),
            Error::Storage(_) => rpc_error("internal-error", "storage error"),
            Error::Io(_) => rpc_error("internal-error", "io error"),
            Error::Serde(_) => rpc_error("invalid-params", "malformed request"),
            Error::Other(m) => rpc_error("internal-error", *m),
        }
    }
}

impl From<Error> for RpcError {
    fn from(e: Error) -> Self {
        (&e).into()
    }
}

// -------------------------------------------------------------------------
// Frame helpers
// -------------------------------------------------------------------------

/// Read one length-prefixed frame from `r`.
///
/// On any short read, oversize length, or I/O error the function returns
/// a typed [`Error::IpcFraming`] and the caller is expected to drop the
/// connection.
pub async fn read_frame<R>(r: &mut R) -> Result<Frame>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| Error::IpcFraming("short read on length prefix"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(Error::IpcFraming("frame exceeds 4 MiB"));
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut body)
            .await
            .map_err(|_| Error::IpcFraming("short read on frame body"))?;
    }
    Ok(Frame(body))
}

/// Write one length-prefixed frame to `w`.
///
/// Returns [`Error::IpcFraming`] if the payload exceeds the 4 MiB cap;
/// the underlying writer is left in whatever state the caller passed.
pub async fn write_frame<W>(w: &mut W, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    if body.len() > MAX_FRAME_SIZE {
        return Err(Error::IpcFraming("outgoing frame exceeds 4 MiB"));
    }
    let len = (body.len() as u32).to_le_bytes();
    w.write_all(&len)
        .await
        .map_err(|_| Error::IpcFraming("write failed (length prefix)"))?;
    w.write_all(body)
        .await
        .map_err(|_| Error::IpcFraming("write failed (frame body)"))?;
    w.flush()
        .await
        .map_err(|_| Error::IpcFraming("flush failed"))?;
    Ok(())
}

/// Read one frame and parse it as a JSON [`Request`].
pub async fn read_request_json<R>(r: &mut R) -> Result<Request>
where
    R: AsyncReadExt + Unpin,
{
    let frame = read_frame(r).await?;
    let req: Request = serde_json::from_slice(&frame.0)
        .map_err(|_| Error::IpcFraming("malformed JSON request"))?;
    Ok(req)
}

/// Serialize a [`Response`] and write it as a single frame.
pub async fn write_response_json<W>(w: &mut W, resp: &Response) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let body = serde_json::to_vec(resp)?;
    write_frame(w, &body).await
}

/// Read one frame and parse it as a JSON [`Response`] (used by clients
/// and tests).
pub async fn read_response_json<R>(r: &mut R) -> Result<Response>
where
    R: AsyncReadExt + Unpin,
{
    let frame = read_frame(r).await?;
    let resp: Response = serde_json::from_slice(&frame.0)
        .map_err(|_| Error::IpcFraming("malformed JSON response"))?;
    Ok(resp)
}

/// Serialize a [`Request`] and write it as a single frame (clients/tests).
pub async fn write_request_json<W>(w: &mut W, req: &Request) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let body = serde_json::to_vec(req)?;
    write_frame(w, &body).await
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = duplex(64 * 1024);
        let payload = b"hello, frame".to_vec();
        write_frame(&mut a, &payload).await.unwrap();
        let f = read_frame(&mut b).await.unwrap();
        assert_eq!(f.0, payload);
    }

    #[tokio::test]
    async fn empty_frame_roundtrip() {
        let (mut a, mut b) = duplex(64);
        write_frame(&mut a, b"").await.unwrap();
        let f = read_frame(&mut b).await.unwrap();
        assert_eq!(f.0, Vec::<u8>::new());
    }

    #[tokio::test]
    async fn request_response_json_roundtrip() {
        let (mut a, mut b) = duplex(8 * 1024);
        let req = Request {
            id: "uuid-1".into(),
            method: "vault.list".into(),
            params: serde_json::json!({}),
            session_token: Some("tok".into()),
        };
        write_request_json(&mut a, &req).await.unwrap();
        let got = read_request_json(&mut b).await.unwrap();
        assert_eq!(got.id, "uuid-1");
        assert_eq!(got.method, "vault.list");
        assert_eq!(got.session_token.as_deref(), Some("tok"));

        let resp = Response::ok("uuid-1", serde_json::json!({"secrets":[]}));
        write_response_json(&mut a, &resp).await.unwrap();
        let got = read_response_json(&mut b).await.unwrap();
        assert_eq!(got.id, "uuid-1");
        assert!(got.result.is_some());
    }

    #[tokio::test]
    async fn oversize_length_rejected() {
        // Hand-craft a header whose declared length exceeds MAX_FRAME_SIZE.
        let (mut a, mut b) = duplex(16);
        let big = (MAX_FRAME_SIZE as u32 + 1).to_le_bytes();
        a.write_all(&big).await.unwrap();
        // Drop the writer so the reader can observe EOF after the prefix.
        drop(a);
        let r = read_frame(&mut b).await;
        match r {
            Err(Error::IpcFraming(m)) => assert!(m.contains("4 MiB")),
            other => panic!("expected IpcFraming, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_body_rejected() {
        let (mut a, mut b) = duplex(64);
        // Declare 100 bytes, send only 10.
        let prefix = 100u32.to_le_bytes();
        a.write_all(&prefix).await.unwrap();
        a.write_all(&[0u8; 10]).await.unwrap();
        drop(a);
        let r = read_frame(&mut b).await;
        match r {
            Err(Error::IpcFraming(m)) => assert!(m.contains("body")),
            other => panic!("expected IpcFraming, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_json_rejected() {
        let (mut a, mut b) = duplex(64);
        write_frame(&mut a, b"not-json{").await.unwrap();
        let r = read_request_json(&mut b).await;
        match r {
            Err(Error::IpcFraming(m)) => assert!(m.contains("malformed")),
            other => panic!("expected IpcFraming, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn outbound_oversize_rejected() {
        let (mut a, _b) = duplex(64);
        let big = vec![0u8; MAX_FRAME_SIZE + 1];
        let r = write_frame(&mut a, &big).await;
        match r {
            Err(Error::IpcFraming(m)) => assert!(m.contains("4 MiB")),
            other => panic!("expected IpcFraming, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn short_read_on_length() {
        let (mut a, mut b) = duplex(64);
        // Write only 2 bytes of the 4-byte prefix.
        a.write_all(&[0u8, 0u8]).await.unwrap();
        drop(a);
        let r = read_frame(&mut b).await;
        assert!(matches!(r, Err(Error::IpcFraming(_))));
    }

    #[test]
    fn rpc_error_helper() {
        let e = rpc_error("invalid-params", "bad");
        assert_eq!(e.code, "invalid-params");
        assert_eq!(e.message, "bad");
    }

    #[test]
    fn error_to_rpcerror_mapping() {
        let cases: Vec<(Error, &str)> = vec![
            (Error::PeerNotTrusted, "peer-not-trusted"),
            (Error::SessionExpired, "session-expired"),
            (Error::SecretExists("x".into()), "secret-exists"),
            (Error::SecretNotFound("x".into()), "secret-not-found"),
            (Error::PolicyDenied("nope".into()), "policy-denied"),
            (Error::ConfirmationRejected, "confirmation-rejected"),
            (Error::Aead("tag mismatch"), "aead-failure"),
            (Error::AuditChainBroken(7), "audit-broken"),
            (Error::Other("oops"), "internal-error"),
        ];
        for (e, code) in cases {
            let r: RpcError = (&e).into();
            assert_eq!(r.code, code, "for {e:?}");
        }
    }
}
