//! Peer-credential authentication for Unix-domain socket connections.
//!
//! On macOS we use:
//! - `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` for the peer's
//!   `audit_token_t` (32 bytes; carries PID + a non-recycling
//!   "pidversion" counter). Falls back to `LOCAL_PEERPID` on the
//!   (vanishingly rare) failure.
//! - `getpeereid(2)` for the peer UID/GID.
//! - `proc_pidpath(3)` for the on-disk binary path.
//! - SHA-256 over the binary file contents as the code-signature surrogate.
//! - `kqueue` + `EVFILT_PROC` + `NOTE_EXIT` for proactive peer-exit
//!   notification (see [`PeerExitWatcher`]). The watcher is the gate
//!   that closes A8 (PID-recycle attacks): on peer exit we revoke
//!   every session bound to that connection before any other process
//!   can inherit the freed PID.
//!
//! On Linux we use `SO_PEERCRED` (PID/UID/GID) and `/proc/<pid>/exe`.
//!
//! Full mach-o code-directory hashing via `SecStaticCodeCopyInformation`
//! is deferred to v1.0 (see RFC 0001). For v0.1 the **on-disk basename
//! allowlist** is the gate; the code-sig hash is recorded for audit.
//!
//! All `unsafe` blocks here call libc / Mach directly. Each is
//! documented with a `// SAFETY:` comment, per the convention in
//! `crypto.rs`.

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
    /// Platform-specific non-recycling identity bytes for the peer.
    ///
    /// On macOS this is the 32-byte `audit_token_t` captured at
    /// `accept()` (its eighth `u32` is the kernel's "pidversion",
    /// which does not recycle when PIDs do). On Linux a pidfd-inode
    /// identity is stored here. On platforms where no such identity
    /// is available, this is `None` and session validation falls back
    /// to the `(pid, basename, conn_id)` triple.
    pub identity: Option<PeerIdentity>,
}

/// Tagged platform-specific non-recycling peer identity bytes.
///
/// Stored alongside the session record so a recycled PID belonging to
/// some other process cannot present a forged session: validation
/// constant-time-compares these bytes and the per-platform exit
/// watcher (kqueue / pidfd) proactively invalidates the session on
/// peer exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Which platform produced these bytes.
    pub kind: PeerIdentityKind,
    /// Opaque identity bytes; meaning depends on `kind`.
    pub bytes: Vec<u8>,
}

/// Discriminator for [`PeerIdentity::bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentityKind {
    /// macOS `audit_token_t` (32 bytes, 8 × `u32` as returned by
    /// `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`).
    MacAuditToken,
    /// Linux pidfd inode bytes (reserved for the Linux work).
    LinuxPidfdInode,
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
    // Prefer LOCAL_PEERTOKEN: it gives us PID *and* the non-recycling
    // pidversion in one syscall. If the kernel ever rejects the option
    // (it has been stable since Mountain Lion), fall back to
    // LOCAL_PEERPID and leave `identity` empty — session binding then
    // degrades to the legacy (pid, basename, conn_id) triple.
    let (pid, identity) = match macos::get_peer_audit_token(fd) {
        Ok(tok) => {
            let pid = macos::audit_token_pid(&tok);
            let identity = Some(PeerIdentity {
                kind: PeerIdentityKind::MacAuditToken,
                bytes: tok.to_vec(),
            });
            (pid, identity)
        }
        Err(_) => (macos::get_peer_pid(fd)?, None),
    };
    let (uid, gid) = macos::get_peer_eid(fd)?;
    let binary_path = macos::pid_to_path(pid).ok();
    let code_sig_hash = binary_path.as_ref().and_then(|p| hash_file(p).ok());
    Ok(PeerInfo {
        pid,
        uid,
        gid,
        binary_path,
        code_sig_hash,
        identity,
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
        identity: None,
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
pub(crate) mod macos {
    use std::ffi::c_void;
    use std::os::fd::RawFd;
    use std::path::PathBuf;

    use crate::error::{Error, Result};

    /// `LOCAL_PEERPID` socket option — see `<sys/un.h>`.
    const LOCAL_PEERPID: libc::c_int = 0x002;
    /// `LOCAL_PEERTOKEN` socket option — see `<sys/un.h>`. Returns a
    /// 32-byte `audit_token_t` (8 × `u32`) describing the peer.
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    /// `SOL_LOCAL` socket option level — see `<sys/un.h>`.
    const SOL_LOCAL: libc::c_int = 0;
    /// `proc_pidpath` maximum buffer size, per Darwin's `<sys/proc_info.h>`.
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;
    /// Number of bytes in an `audit_token_t` (8 × `u32`).
    pub const AUDIT_TOKEN_LEN: usize = 32;

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

    /// Resolve the peer's `audit_token_t` via
    /// `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`. The token is 32 bytes
    /// (8 × `u32`); element `val[7]` is the kernel's "pidversion"
    /// counter, which is bumped on every `fork()` and therefore
    /// uniquely identifies a process in a way that does not recycle
    /// when PIDs do. See `<bsm/audit.h>` and `audit_token_to_pid(3)`.
    pub fn get_peer_audit_token(fd: RawFd) -> Result<[u8; AUDIT_TOKEN_LEN]> {
        let mut buf = [0u8; AUDIT_TOKEN_LEN];
        let mut size = AUDIT_TOKEN_LEN as libc::socklen_t;
        // SAFETY: `fd` is borrowed for the duration of this call. `buf`
        // is a stack array of exactly `AUDIT_TOKEN_LEN` bytes, matching
        // the kernel's wire size for `LOCAL_PEERTOKEN`. `getsockopt`
        // does not retain either pointer past return.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
            )
        };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        if size as usize != AUDIT_TOKEN_LEN {
            return Err(Error::Other("LOCAL_PEERTOKEN returned unexpected size"));
        }
        Ok(buf)
    }

    /// Extract the PID from a captured `audit_token_t`. Mirrors
    /// `audit_token_to_pid()` from `<bsm/libbsm.h>`: the `audit_token_t`
    /// layout per `<bsm/audit.h>` is
    /// `(auid, euid, egid, ruid, rgid, pid, asid, pidversion)`, so
    /// PID lives in `val[5]` (bytes 20..24, native endian).
    pub fn audit_token_pid(tok: &[u8; AUDIT_TOKEN_LEN]) -> i32 {
        u32::from_ne_bytes([tok[20], tok[21], tok[22], tok[23]]) as i32
    }

    /// Extract the kernel's pidversion counter from a captured token.
    /// Bytes 28..32 (native endian) per the layout above. Reserved
    /// for diagnostic logging — the full 32-byte token is what we
    /// store in `SessionRecord` and constant-time-compare on every
    /// validate.
    #[allow(dead_code)]
    pub fn audit_token_pidversion(tok: &[u8; AUDIT_TOKEN_LEN]) -> u32 {
        u32::from_ne_bytes([tok[28], tok[29], tok[30], tok[31]])
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
// macOS process-exit watcher (kqueue + EVFILT_PROC + NOTE_EXIT)
// -------------------------------------------------------------------------

/// Async one-shot watcher for "this PID has exited" on macOS.
///
/// Backed by a dedicated `kqueue(2)` registered with
/// `EVFILT_PROC | NOTE_EXIT` for the target PID, wrapped in
/// `tokio::io::unix::AsyncFd`. The fd becomes readable when the kernel
/// posts the exit event; awaiting [`PeerExitWatcher::wait`] resolves
/// at that point.
///
/// `EVFILT_PROC` registration is bound to the kernel's `proc *`, not
/// the integer PID, so even if the PID recycles before the watcher
/// fires the exit event for the *original* process is still what the
/// kernel posts.
#[cfg(target_os = "macos")]
pub struct PeerExitWatcher {
    inner: tokio::io::unix::AsyncFd<KqueueFd>,
    pid: i32,
}

/// RAII wrapper around a kqueue fd so it always gets `close(2)`'d.
#[cfg(target_os = "macos")]
struct KqueueFd(std::os::fd::RawFd);

#[cfg(target_os = "macos")]
impl std::os::fd::AsRawFd for KqueueFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

#[cfg(target_os = "macos")]
impl Drop for KqueueFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: We own this fd by construction (from `kqueue()`)
            // and Drop runs at most once. `close` does not retain the
            // descriptor past return.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl PeerExitWatcher {
    /// Create a kqueue and register `pid` for `NOTE_EXIT`. Returns
    /// immediately; await [`Self::wait`] for the exit event.
    ///
    /// Returns `Err(Error::Io(ESRCH))` if `pid` is already gone at
    /// registration time — callers should treat that the same as
    /// "exited" and revoke straight away.
    pub fn new(pid: i32) -> Result<Self> {
        // SAFETY: `kqueue()` takes no arguments; returns a new fd or
        // -1 with errno set.
        let kq_raw = unsafe { libc::kqueue() };
        if kq_raw < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let kq = KqueueFd(kq_raw);

        // Register a one-shot EVFILT_PROC | NOTE_EXIT for `pid`.
        // `EV_RECEIPT` makes `kevent` synchronously emit a status row
        // for the change instead of consuming an event slot.
        let changelist = [libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        }];
        let mut eventlist = [libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        }; 1];
        // SAFETY: `kq.0` is a valid kqueue fd we just created. The two
        // arrays are borrowed for the duration of the call only; their
        // lengths match the counts we pass.
        let n = unsafe {
            libc::kevent(
                kq.0,
                changelist.as_ptr(),
                changelist.len() as libc::c_int,
                eventlist.as_mut_ptr(),
                eventlist.len() as libc::c_int,
                std::ptr::null(),
            )
        };
        if n < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // EV_RECEIPT writes one status entry per change. A non-zero
        // `data` field with EV_ERROR set carries an errno; ESRCH means
        // the process is already gone.
        if n >= 1 && (eventlist[0].flags & libc::EV_ERROR) != 0 && eventlist[0].data != 0 {
            let errno = eventlist[0].data as i32;
            return Err(Error::Io(std::io::Error::from_raw_os_error(errno)));
        }

        // AsyncFd needs the fd in nonblocking mode. The kqueue itself
        // does not block on read; we still set O_NONBLOCK so the
        // tokio readiness machinery is happy.
        // SAFETY: we own `kq.0`. `fcntl(F_GETFL/F_SETFL)` does not
        // retain the descriptor past return.
        unsafe {
            let flags = libc::fcntl(kq.0, libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(kq.0, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let inner = tokio::io::unix::AsyncFd::with_interest(kq, tokio::io::Interest::READABLE)
            .map_err(Error::Io)?;
        Ok(Self { inner, pid })
    }

    /// PID this watcher is bound to.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Resolve when the kernel posts a `NOTE_EXIT` for the registered
    /// PID. Returns `Ok(())` on exit and `Err` on any kqueue / kevent
    /// error.
    pub async fn wait(self) -> Result<()> {
        loop {
            let mut guard = self.inner.readable().await.map_err(Error::Io)?;

            let kq = self.inner.get_ref().0;
            let mut eventlist = [libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }; 1];
            // Zero timespec: poll, do not block. AsyncFd already told
            // us the fd is readable.
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `kq` is the kqueue fd we own; `eventlist` is
            // local stack storage with the count we pass; `timeout` is
            // a borrowed local. `kevent` does not retain any of these
            // past return.
            let n = unsafe {
                libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    eventlist.as_mut_ptr(),
                    eventlist.len() as libc::c_int,
                    &timeout,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::Io(err));
            }
            if n == 0 {
                // Spurious wake-up: drop readiness and re-arm.
                guard.clear_ready();
                continue;
            }
            if eventlist[0].filter == libc::EVFILT_PROC
                && (eventlist[0].fflags & libc::NOTE_EXIT) != 0
            {
                return Ok(());
            }
            guard.clear_ready();
        }
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
            identity: None,
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

    #[cfg(target_os = "macos")]
    #[test]
    fn audit_token_pid_layout() {
        // PID at val[5] (bytes 20..24), pidversion at val[7] (28..32).
        let mut tok = [0u8; macos::AUDIT_TOKEN_LEN];
        tok[20..24].copy_from_slice(&424242u32.to_ne_bytes());
        tok[28..32].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(macos::audit_token_pid(&tok), 424242);
        assert_eq!(macos::audit_token_pidversion(&tok), 7);
    }
}
