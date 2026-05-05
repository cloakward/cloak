//! Hash-chained JSONL audit log.
//!
//! Entries are appended one JSON object per line. Each entry's `prev_hash`
//! field is the lowercase-hex SHA-256 of the canonical (RFC 8785 / JCS)
//! serialization of the previous entry. The first entry's `prev_hash` is
//! `"0".repeat(64)`. Tamper detection relies on recomputing the chain from
//! the start.
//!
//! Audit entries **never** contain secret values. Tests use placeholders.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha256;
use crate::error::{Error, Result};

/// Outcome recorded for an audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// The operation was allowed and succeeded.
    Ok,
    /// The operation was denied by policy.
    Denied,
    /// The operation errored after authorization.
    Error,
}

/// Lightweight summary of the calling peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSummary {
    /// Process id.
    pub pid: i32,
    /// File basename of the calling executable.
    pub basename: String,
    /// Hex-encoded code signature digest (if known).
    pub code_sig_hex: Option<String>,
}

/// A single record on the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number, starting at 1.
    pub seq: u64,
    /// UTC timestamp of when the entry was appended.
    pub ts: DateTime<Utc>,
    /// Calling peer summary.
    pub peer: PeerSummary,
    /// Method/tool name, e.g. `tool.sign_request`.
    pub tool: String,
    /// Secret name involved, if any.
    pub secret: Option<String>,
    /// Target host or URL (for proxy_http and similar).
    pub target: Option<String>,
    /// Outcome of the operation.
    pub result: AuditResult,
    /// Free-form short message; never contains secret values.
    pub note: Option<String>,
    /// Lowercase hex SHA-256 of the canonical JSON of the prior entry.
    pub prev_hash: String,
}

/// All caller-supplied fields needed to construct a new [`AuditEntry`].
#[derive(Debug, Clone)]
pub struct AuditDraft {
    /// Calling peer summary.
    pub peer: PeerSummary,
    /// Method/tool name.
    pub tool: String,
    /// Secret name involved, if any.
    pub secret: Option<String>,
    /// Target host or URL.
    pub target: Option<String>,
    /// Outcome.
    pub result: AuditResult,
    /// Free-form short message.
    pub note: Option<String>,
}

/// Filter for [`AuditLog::query`].
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Lower bound (inclusive) on `ts`.
    pub since: Option<DateTime<Utc>>,
    /// Upper bound (inclusive) on `ts`.
    pub until: Option<DateTime<Utc>>,
    /// Filter on tool name (exact match).
    pub tool: Option<String>,
    /// Filter on secret name (exact match).
    pub secret: Option<String>,
    /// Filter on result.
    pub result: Option<AuditResult>,
    /// Maximum number of entries to return. `0` means no cap.
    pub limit: usize,
}

/// All-zero hex string used as the genesis `prev_hash`.
const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only hash-chained audit log.
pub struct AuditLog {
    path: PathBuf,
    last_seq: u64,
    last_hash: String,
}

impl AuditLog {
    /// Open or create an audit log at `path`. Reads the tail to recover the
    /// most recent `(seq, computed_hash)` so subsequent appends form a
    /// consistent chain.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Touch the file to ensure it exists with the right mode.
        let _ = open_appendable(path)?;

        let (last_seq, last_hash) = recover_tail(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            last_seq,
            last_hash,
        })
    }

    /// Append `draft` as a new entry. Atomic w.r.t. concurrent appenders via
    /// an exclusive flock + `O_APPEND`.
    pub fn append(&mut self, draft: AuditDraft) -> Result<AuditEntry> {
        let mut file = open_appendable(&self.path)?;
        // Acquire exclusive lock; blocks until other appenders release.
        FileExt::lock_exclusive(&file)?;

        // Re-read tail under the lock so multi-process appenders converge.
        let (last_seq, last_hash) = read_tail_from_open(&mut file)?;
        if last_seq > self.last_seq {
            self.last_seq = last_seq;
            self.last_hash = last_hash;
        } else if last_seq == 0 {
            // Empty file: keep cached genesis.
            self.last_seq = 0;
            self.last_hash = GENESIS_PREV.to_string();
        }

        let entry = AuditEntry {
            seq: self.last_seq + 1,
            ts: Utc::now(),
            peer: draft.peer,
            tool: draft.tool,
            secret: draft.secret,
            target: draft.target,
            result: draft.result,
            note: draft.note,
            prev_hash: self.last_hash.clone(),
        };

        // Pretty-on-disk uses serde_json single-line; the hash is over JCS.
        let line = serde_json::to_string(&entry)?;
        // Sanity — never embed a newline in a single record.
        debug_assert!(!line.contains('\n'));

        // Move to end of file before writing (O_APPEND should already do
        // this on Unix, but explicit seek matches Windows semantics too).
        file.seek(SeekFrom::End(0))?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_data()?;

        // Compute new chain head hash from the entry's canonical form.
        let canonical = serde_jcs::to_string(&entry)
            .map_err(|_| Error::Other("audit: canonical json failed"))?;
        self.last_seq = entry.seq;
        self.last_hash = hex_lower(&sha256(canonical.as_bytes()));

        // Lock drops on file close at the end of this scope.
        let _ = FileExt::unlock(&file);
        Ok(entry)
    }

    /// Verify the full chain. Returns the number of entries.
    ///
    /// On any mismatch — bad JSON, non-monotonic seq, or hash break — returns
    /// [`Error::AuditChainBroken`] with the 1-based line number.
    pub fn verify(&self) -> Result<u64> {
        let f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let reader = BufReader::new(f);

        let mut prev_seq: u64 = 0;
        let mut prev_hash = GENESIS_PREV.to_string();
        let mut count: u64 = 0;
        for (idx, line) in reader.lines().enumerate() {
            let line_no = (idx as u64) + 1;
            let line = line.map_err(|_| Error::AuditChainBroken(line_no))?;
            if line.is_empty() {
                return Err(Error::AuditChainBroken(line_no));
            }
            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|_| Error::AuditChainBroken(line_no))?;
            if entry.seq != prev_seq + 1 {
                return Err(Error::AuditChainBroken(line_no));
            }
            if entry.prev_hash != prev_hash {
                return Err(Error::AuditChainBroken(line_no));
            }
            let canonical =
                serde_jcs::to_string(&entry).map_err(|_| Error::AuditChainBroken(line_no))?;
            prev_hash = hex_lower(&sha256(canonical.as_bytes()));
            prev_seq = entry.seq;
            count += 1;
        }
        Ok(count)
    }

    /// Return the last `n` entries (or all of them if fewer exist).
    pub fn tail(&self, n: usize) -> Result<Vec<AuditEntry>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let entries = read_all_entries(&self.path)?;
        let start = entries.len().saturating_sub(n);
        Ok(entries[start..].to_vec())
    }

    /// Return entries matching `filter`, capped at `filter.limit` (0 = no cap).
    pub fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let entries = read_all_entries(&self.path)?;
        let mut out = Vec::new();
        for e in entries.into_iter() {
            if let Some(since) = filter.since {
                if e.ts < since {
                    continue;
                }
            }
            if let Some(until) = filter.until {
                if e.ts > until {
                    continue;
                }
            }
            if let Some(t) = &filter.tool {
                if &e.tool != t {
                    continue;
                }
            }
            if let Some(s) = &filter.secret {
                if e.secret.as_deref() != Some(s.as_str()) {
                    continue;
                }
            }
            if let Some(r) = filter.result {
                if e.result != r {
                    continue;
                }
            }
            out.push(e);
            if filter.limit != 0 && out.len() >= filter.limit {
                break;
            }
        }
        Ok(out)
    }
}

// ------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------

fn hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn open_appendable(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

/// Read the entire file once and return the parsed `(last_seq, last_hash)`.
/// `last_hash` is the SHA-256 of the canonical form of the last entry, or
/// the all-zero genesis if the file is empty.
fn recover_tail(path: &Path) -> Result<(u64, String)> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, GENESIS_PREV.to_string()))
        }
        Err(e) => return Err(e.into()),
    };
    let reader = BufReader::new(f);
    let mut last_seq = 0u64;
    let mut last_hash = GENESIS_PREV.to_string();
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)?;
        let canonical = serde_jcs::to_string(&entry)
            .map_err(|_| Error::Other("audit: canonical json failed"))?;
        last_hash = hex_lower(&sha256(canonical.as_bytes()));
        last_seq = entry.seq;
    }
    Ok((last_seq, last_hash))
}

fn read_tail_from_open(f: &mut File) -> Result<(u64, String)> {
    f.seek(SeekFrom::Start(0))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    let mut last_seq = 0u64;
    let mut last_hash = GENESIS_PREV.to_string();
    for line in buf.lines() {
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)?;
        let canonical = serde_jcs::to_string(&entry)
            .map_err(|_| Error::Other("audit: canonical json failed"))?;
        last_hash = hex_lower(&sha256(canonical.as_bytes()));
        last_seq = entry.seq;
    }
    Ok((last_seq, last_hash))
}

fn read_all_entries(path: &Path) -> Result<Vec<AuditEntry>> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)?;
        out.push(entry);
    }
    Ok(out)
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tempfile::tempdir;

    fn peer() -> PeerSummary {
        PeerSummary {
            pid: 1234,
            basename: "test".to_string(),
            code_sig_hex: Some("deadbeef".to_string()),
        }
    }

    fn draft(tool: &str, secret: Option<&str>, result: AuditResult) -> AuditDraft {
        AuditDraft {
            peer: peer(),
            tool: tool.to_string(),
            secret: secret.map(str::to_string),
            target: None,
            result,
            note: Some("REDACTED".to_string()),
        }
    }

    #[test]
    fn open_creates_parent_dirs_and_starts_empty() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("nested/dir/audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        assert_eq!(log.last_seq, 0);
        assert_eq!(log.last_hash, GENESIS_PREV);
        assert_eq!(log.verify().unwrap(), 0);
    }

    #[test]
    fn append_one_then_verify() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        let e = log
            .append(draft("tool.sign_request", Some("S1"), AuditResult::Ok))
            .unwrap();
        assert_eq!(e.seq, 1);
        assert_eq!(e.prev_hash, GENESIS_PREV);
        assert_eq!(log.verify().unwrap(), 1);
    }

    #[test]
    fn append_100_and_verify() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        for i in 0..100 {
            let r = if i % 3 == 0 {
                AuditResult::Ok
            } else if i % 3 == 1 {
                AuditResult::Denied
            } else {
                AuditResult::Error
            };
            log.append(draft("tool.sign_request", Some("S1"), r))
                .unwrap();
        }
        assert_eq!(log.verify().unwrap(), 100);
    }

    #[test]
    fn tail_returns_last_n() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        for _ in 0..10 {
            log.append(draft("tool.sign_request", None, AuditResult::Ok))
                .unwrap();
        }
        let last3 = log.tail(3).unwrap();
        assert_eq!(last3.len(), 3);
        assert_eq!(last3[0].seq, 8);
        assert_eq!(last3[2].seq, 10);
        let all_more = log.tail(99).unwrap();
        assert_eq!(all_more.len(), 10);
        assert!(log.tail(0).unwrap().is_empty());
    }

    #[test]
    fn reopen_recovers_chain() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        {
            let mut log = AuditLog::open(&p).unwrap();
            for _ in 0..5 {
                log.append(draft("tool.x", None, AuditResult::Ok)).unwrap();
            }
        }
        // Re-open and append; chain should remain valid.
        let mut log = AuditLog::open(&p).unwrap();
        assert_eq!(log.last_seq, 5);
        let e = log.append(draft("tool.x", None, AuditResult::Ok)).unwrap();
        assert_eq!(e.seq, 6);
        assert_eq!(log.verify().unwrap(), 6);
    }

    #[test]
    fn mutated_byte_breaks_verify() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        for _ in 0..10 {
            log.append(draft("tool.x", Some("S"), AuditResult::Ok))
                .unwrap();
        }
        // Flip one character of the third entry's "note" field.
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        lines[2] = lines[2].replace("\"REDACTED\"", "\"REDACTEX\"");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        let log2 = AuditLog::open(&p).unwrap();
        match log2.verify() {
            // When seq3's hash chain breaks, the *next* line (4) is what
            // notices the mismatch via prev_hash.
            Err(Error::AuditChainBroken(line_no)) => assert_eq!(line_no, 4),
            other => panic!("expected AuditChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn deleted_line_breaks_verify() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        for _ in 0..6 {
            log.append(draft("tool.x", None, AuditResult::Ok)).unwrap();
        }
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        // Delete the 3rd line.
        lines.remove(2);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        let log2 = AuditLog::open(&p).unwrap();
        match log2.verify() {
            Err(Error::AuditChainBroken(_)) => {}
            other => panic!("expected break, got {other:?}"),
        }
    }

    #[test]
    fn reordered_lines_break_verify() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        for _ in 0..5 {
            log.append(draft("tool.x", None, AuditResult::Ok)).unwrap();
        }
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        // Swap lines 3 and 4 (0-indexed 2 and 3).
        lines.swap(2, 3);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        let log2 = AuditLog::open(&p).unwrap();
        assert!(matches!(log2.verify(), Err(Error::AuditChainBroken(_))));
    }

    #[test]
    fn concurrent_appends_are_atomic_and_complete() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let log = Arc::new(Mutex::new(AuditLog::open(&p).unwrap()));
        let mut handles = Vec::new();
        for t in 0..4 {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for i in 0..25 {
                    let mut g = log.lock().unwrap();
                    let note = format!("t{t}-i{i}");
                    g.append(AuditDraft {
                        peer: peer(),
                        tool: "tool.x".to_string(),
                        secret: None,
                        target: None,
                        result: AuditResult::Ok,
                        note: Some(note),
                    })
                    .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let g = log.lock().unwrap();
        assert_eq!(g.verify().unwrap(), 100);
        let entries = read_all_entries(&p).unwrap();
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq as usize, i + 1);
        }
    }

    #[test]
    fn query_filters_by_tool_secret_result_and_time() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        log.append(draft("tool.a", Some("S1"), AuditResult::Ok))
            .unwrap();
        log.append(draft("tool.b", Some("S2"), AuditResult::Denied))
            .unwrap();
        log.append(draft("tool.a", Some("S2"), AuditResult::Ok))
            .unwrap();
        log.append(draft("tool.b", Some("S1"), AuditResult::Error))
            .unwrap();

        let by_tool = log
            .query(&AuditFilter {
                tool: Some("tool.a".to_string()),
                limit: 0,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_tool.len(), 2);

        let by_secret = log
            .query(&AuditFilter {
                secret: Some("S1".to_string()),
                limit: 0,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_secret.len(), 2);

        let by_result = log
            .query(&AuditFilter {
                result: Some(AuditResult::Denied),
                limit: 0,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_result.len(), 1);

        let limited = log
            .query(&AuditFilter {
                limit: 2,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(limited.len(), 2);

        let entries = read_all_entries(&p).unwrap();
        let t_mid = entries[1].ts;
        let since = log
            .query(&AuditFilter {
                since: Some(t_mid),
                limit: 0,
                ..Default::default()
            })
            .unwrap();
        assert!(since.iter().all(|e| e.ts >= t_mid));
        let until = log
            .query(&AuditFilter {
                until: Some(t_mid),
                limit: 0,
                ..Default::default()
            })
            .unwrap();
        assert!(until.iter().all(|e| e.ts <= t_mid));
    }

    #[test]
    fn first_entry_has_genesis_prev_hash() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        let e = log.append(draft("tool.x", None, AuditResult::Ok)).unwrap();
        assert_eq!(e.prev_hash, GENESIS_PREV);
        assert_eq!(e.prev_hash.len(), 64);
        assert!(e.prev_hash.chars().all(|c| c == '0'));
    }
}
