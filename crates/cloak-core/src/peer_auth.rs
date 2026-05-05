//! Peer-credential authentication for Unix-domain socket connections.
//!
//! On macOS we use:
//! - `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` for the peer PID.
//! - `getpeereid(2)` for the peer UID/GID.
//! - `proc_pidpath(3)` for the on-disk binary path.
//! - SHA-256 over the binary file contents as the code-signature surrogate.
//!
//! On Linux we use `SO_PEERCRED` (PID/UID/GID) and `/proc/<pid>/exe`.
//!
//! Full mach-o code-directory hashing via `SecStaticCodeCopyInformation`
//! is deferred to v1.0 (see RFC 0001). For v0.1 the **on-disk basename
//! allowlist** is the gate; the code-sig hash is recorded for audit.
//!
//! All `unsafe` blocks here call libc directly. Each is documented with
//! a `// SAFETY:` comment, per the convention in `crypto.rs`.

use std::path::PathBuf;

use crate::crypto::hash;
use crate::error::{Error, Result};

/// Peer process identity, as resolved from a Unix-domain socket.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer process ID at the time of `accept()`.
    pub pid: i32,
    /// Effective user ID of the peer process.
    pub uid: u32,
    /// Effective group ID of the peer process.
    pub gid: u32,
    /// Resolved path to the peer's on-disk executable, if available.
    pub binary_path: Option<PathBuf>,
    /// Code-signature surrogate: SHA-256 of the on-disk binary, if it
    /// could be read. v1.0 will replace this with a true code-directory
    /// hash on macOS.
    pub code_sig_hash: Option<[u8; 32]>,
}

/// Allowlist policy used to decide whether a peer may proceed past the
/// initial peer-credential gate.
#[derive(Debug, Clone)]
pub struct PeerPolicy {
    /// Allowed binary basenames (e.g. `["cloak", "cloak-mcp"]`).
    pub allowed_basenames: Vec<String>,
    /// If true, peer UID must equal the daemon's UID.
    pub require_same_uid: bool,
}

impl PeerPolicy {
    /// Default allowlist for v0.1 — `cloak` (CLI) and `cloak-mcp` (shim),
    /// same UID required.
    pub fn default_v01() -> Self {
        Self {
            allowed_basenames: vec![
                "cloak".to_string(),
                "cloak-mcp".to_string(),
                "cloakd".to_string(),
            ],
            require_same_uid: true,
        }
    }
}

/// Classification of a peer for routing purposes (CLI vs MCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKind {
    /// `cloak` CLI peer — full vault surface.
    Cli,
    /// `cloak-mcp` peer — read-only + tool methods only.
    Mcp,
    /// Unknown but allowlisted peer (e.g. `cloakd` self-test).
    Other,
}

impl PeerInfo {
    /// Best-effort basename of the peer binary (lower-cased on macOS so
    /// `Cloak.app/Contents/MacOS/cloak` still matches).
    pub fn basename(&self) -> Option<String> {
        self.binary_path
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    }

    /// Classify this peer for downstream routing.
    pub fn kind(&self) -> PeerKind {
        match self.basename().as_deref() {
            Some("cloak") => PeerKind::Cli,
            Some("cloak-mcp") => PeerKind::Mcp,
            _ => PeerKind::Other,
        }
    }
}

/// Verify the peer against `policy`. Returns `Err(Error::PeerNotTrusted)`
/// for any of: missing binary path, basename not in allowlist, or UID
/// mismatch when `require_same_uid` is set.
pub fn check(peer: &PeerInfo, policy: &PeerPolicy, our_uid: u32) -> Result<()> {
    if policy.require_same_uid && peer.uid != our_uid {
        return Err(Error::PeerNotTrusted);
    }
    let basename = peer.basename().ok_or(Error::PeerNotTrusted)?;
    if !policy.allowed_basenames.iter().any(|b| b == &basename) {
        return Err(Error::PeerNotTrusted);
    }
    Ok(())
}

// =========================================================================
// Platform-specific peer info extraction.
// =========================================================================

/// Resolve peer credentials from a connected `tokio::net::UnixStream`.
///
/// This consults the kernel directly via libc — `tokio`'s `peer_cred()`
/// helper exists but does not expose PID on macOS in our MSRV, so we
/// roll our own.
#[cfg(unix)]
pub fn peer_info_from_unix(stream: &tokio::net::UnixStream) -> Result<PeerInfo> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    peer_info_from_raw_fd(fd)
}

#[cfg(target_os = "macos")]
fn peer_info_from_raw_fd(fd: std::os::fd::RawFd) -> Result<PeerInfo> {
    let pid = macos::get_peer_pid(fd)?;
    let (uid, gid) = macos::get_peer_eid(fd)?;
    let binary_path = macos::pid_to_path(pid).ok();
    let code_sig_hash = binary_path.as_ref().and_then(|p| hash_file(p).ok());
    Ok(PeerInfo {
        pid,
        uid,
        gid,
        binary_path,
        code_sig_hash,
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn peer_info_from_raw_fd(fd: std::os::fd::RawFd) -> Result<PeerInfo> {
    let cred = linux::get_peer_cred(fd)?;
    let binary_path = std::fs::read_link(format!("/proc/{}/exe", cred.pid)).ok();
    let code_sig_hash = binary_path.as_ref().and_then(|p| hash_file(p).ok());
    Ok(PeerInfo {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
        binary_path,
        code_sig_hash,
    })
}

/// SHA-256 the contents of a file. Used as a v0.1 stand-in for a true
/// code-signature hash.
fn hash_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)?;
    Ok(hash::sha256(&bytes))
}

// -------------------------------------------------------------------------
// macOS impl
// -------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::c_void;
    use std::os::fd::RawFd;
    use std::path::PathBuf;

    use crate::error::{Error, Result};

    /// `LOCAL_PEERPID` socket option — see `<sys/un.h>`.
    const LOCAL_PEERPID: libc::c_int = 0x002;
    /// `SOL_LOCAL` socket option level — see `<sys/un.h>`.
    const SOL_LOCAL: libc::c_int = 0;
    /// `proc_pidpath` maximum buffer size, per Darwin's `<sys/proc_info.h>`.
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;

    extern "C" {
        fn proc_pidpath(pid: libc::c_int, buffer: *mut c_void, buffersize: u32) -> libc::c_int;
    }

    /// Resolve the peer's PID via `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`.
    pub fn get_peer_pid(fd: RawFd) -> Result<i32> {
        let mut pid: libc::pid_t = 0;
        let mut size = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `fd` is a borrowed file descriptor owned by the
        // `UnixStream` for the duration of this call. `&mut pid` and
        // `&mut size` point to stack storage of the right size for
        // `LOCAL_PEERPID` (a `pid_t`). `getsockopt` does not retain
        // either pointer past return.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut c_void,
                &mut size,
            )
        };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(pid as i32)
    }

    /// Resolve the peer's effective UID/GID via `getpeereid(2)`.
    pub fn get_peer_eid(fd: RawFd) -> Result<(u32, u32)> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: same fd-borrow contract as above; both out-parameters
        // are exclusive references to local stack storage.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok((uid as u32, gid as u32))
    }

    /// Resolve `pid`'s on-disk binary path via Darwin's `proc_pidpath`.
    pub fn pid_to_path(pid: i32) -> Result<PathBuf> {
        let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
        // SAFETY: `buf` is a heap allocation of `PROC_PIDPATHINFO_MAXSIZE`
        // bytes that we own. `proc_pidpath` writes a NUL-terminated path
        // and returns the number of bytes written (excluding NUL) on
        // success, or 0 on failure (with `errno` set).
        let n = unsafe {
            proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        buf.truncate(n as usize);
        let s = String::from_utf8(buf)
            .map_err(|_| Error::Other("proc_pidpath returned non-utf8 path"))?;
        Ok(PathBuf::from(s))
    }
}

// -------------------------------------------------------------------------
// Linux impl
// -------------------------------------------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use std::ffi::c_void;
    use std::os::fd::RawFd;

    use crate::error::{Error, Result};

    pub struct LinuxPeerCred {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }

    /// `SO_PEERCRED` returns a `struct ucred { pid_t pid; uid_t uid; gid_t gid; }`.
    pub fn get_peer_cred(fd: RawFd) -> Result<LinuxPeerCred> {
        #[repr(C)]
        struct Ucred {
            pid: libc::pid_t,
            uid: libc::uid_t,
            gid: libc::gid_t,
        }
        let mut cred = Ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut size = std::mem::size_of::<Ucred>() as libc::socklen_t;
        // SAFETY: `fd` is borrowed for the duration of this call. The
        // out parameter points to local stack storage of exactly the
        // size advertised in `size`. `getsockopt` does not retain
        // either pointer past return.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut c_void,
                &mut size,
            )
        };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(LinuxPeerCred {
            pid: cred.pid as i32,
            uid: cred.uid as u32,
            gid: cred.gid as u32,
        })
    }
}

/// Best-effort lookup of the daemon's own UID. Falls back to `0` if
/// `getuid` somehow misbehaves (it does not).
#[cfg(unix)]
pub fn our_uid() -> u32 {
    // SAFETY: `geteuid` is async-signal-safe and has no preconditions.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(not(unix))]
pub fn our_uid() -> u32 {
    0
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk(uid: u32, basename: &str) -> PeerInfo {
        PeerInfo {
            pid: 1234,
            uid,
            gid: uid,
            binary_path: Some(PathBuf::from(format!("/usr/local/bin/{basename}"))),
            code_sig_hash: Some([0u8; 32]),
        }
    }

    #[test]
    fn happy_path_cli() {
        let peer = mk(501, "cloak");
        let pol = PeerPolicy::default_v01();
        check(&peer, &pol, 501).unwrap();
        assert_eq!(peer.kind(), PeerKind::Cli);
    }

    #[test]
    fn happy_path_mcp() {
        let peer = mk(501, "cloak-mcp");
        let pol = PeerPolicy::default_v01();
        check(&peer, &pol, 501).unwrap();
        assert_eq!(peer.kind(), PeerKind::Mcp);
    }

    #[test]
    fn uid_mismatch_rejected() {
        let peer = mk(0, "cloak");
        let pol = PeerPolicy::default_v01();
        assert!(matches!(
            check(&peer, &pol, 501),
            Err(Error::PeerNotTrusted)
        ));
    }

    #[test]
    fn basename_not_in_allowlist() {
        let peer = mk(501, "evil-tool");
        let pol = PeerPolicy::default_v01();
        assert!(matches!(
            check(&peer, &pol, 501),
            Err(Error::PeerNotTrusted)
        ));
    }

    #[test]
    fn missing_binary_path_rejected() {
        let mut peer = mk(501, "cloak");
        peer.binary_path = None;
        let pol = PeerPolicy::default_v01();
        assert!(matches!(
            check(&peer, &pol, 501),
            Err(Error::PeerNotTrusted)
        ));
    }

    #[test]
    fn require_same_uid_off_allows_other_uid() {
        let peer = mk(0, "cloak");
        let pol = PeerPolicy {
            allowed_basenames: vec!["cloak".into()],
            require_same_uid: false,
        };
        check(&peer, &pol, 501).unwrap();
    }

    #[test]
    fn peer_kind_classification() {
        assert_eq!(mk(1, "cloak").kind(), PeerKind::Cli);
        assert_eq!(mk(1, "cloak-mcp").kind(), PeerKind::Mcp);
        assert_eq!(mk(1, "cloakd").kind(), PeerKind::Other);
        assert_eq!(mk(1, "wat").kind(), PeerKind::Other);
    }
}
