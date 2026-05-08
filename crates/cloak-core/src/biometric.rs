//! Per-platform user-presence / biometric gate, invoked by `cloakd`
//! when serving `vault.show`.
//!
//! Server-side enforcement (since v1.0): the daemon — not the CLI —
//! fires the prompt before any plaintext leaves the vault. A same-UID
//! attacker who connects to the daemon socket directly cannot skip the
//! Touch ID / polkit step by lying in the request payload; the daemon
//! ignores any client-supplied biometric assertion.
//!
//! Each platform exposes the same [`authenticate`] entry point:
//!
//! - **macOS** — Touch ID via the `LocalAuthentication` framework.
//! - **Linux** — polkit's `org.freedesktop.PolicyKit1.Authority`
//!   `CheckAuthorization` D-Bus method against the `dev.cloak.show-secret`
//!   action (default policy `auth_self_keep`, see
//!   `scripts/polkit/dev.cloak.policy`).
//! - **Other** — a stub that returns `Ok(false)`; the daemon then
//!   refuses the reveal unless the caller passed the explicit
//!   `skip_biometric` opt-out.
//!
//! Failure / cancel returns `Ok(false)` so the daemon can refuse the
//! reveal with [`crate::Error::BiometricFailed`].

use anyhow::Result;

#[cfg(target_os = "macos")]
mod imp {
    use anyhow::Result;
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};
    use std::sync::mpsc;
    use std::time::Duration;

    /// How long we'll wait for the user to respond to the Touch ID prompt
    /// before we give up. The system itself enforces shorter timeouts;
    /// this is a belt-and-braces upper bound so a confused tester never
    /// hangs forever.
    const TOUCH_ID_TIMEOUT: Duration = Duration::from_secs(60);

    /// Trigger a Touch ID prompt with the given reason string.
    ///
    /// Returns:
    /// - `Ok(true)` — user authenticated.
    /// - `Ok(false)` — user cancelled, fell back to passphrase, no
    ///   biometric is enrolled, or the device-owner policy is
    ///   unavailable. Caller should treat this as "biometric was not
    ///   confirmed" and act accordingly.
    /// - `Err(_)` — hard failure (channel poisoned, framework returned
    ///   something we can't classify).
    pub fn authenticate(reason: &str) -> Result<bool> {
        // SAFETY: `LAContext::new` is a class-method constructor with no
        // preconditions; the result is a +1-retained instance we own.
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };

        // Step 1: ask whether the policy is even evaluable. If the
        // device has no enrolled biometric, or the user has disabled
        // Touch ID for this app, we return Ok(false) so the caller can
        // fall back gracefully.
        // SAFETY: `canEvaluatePolicy_error` is safe to call on a fresh
        // `LAContext` with a known-valid policy enum value.
        let can_eval = unsafe {
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        };
        if can_eval.is_err() {
            return Ok(false);
        }

        // Step 2: kick off `evaluatePolicy:localizedReason:reply:`. The
        // reply runs on a background queue, so we use a one-shot mpsc
        // channel to relay the result back to this thread.
        let reason_ns = NSString::from_str(reason);
        let (tx, rx) = mpsc::channel::<Result<bool, i64>>();

        // The block is heap-copied (`RcBlock`) so it survives until the
        // framework invokes it. The captured `tx` is dropped when the
        // block is dropped, after the framework releases its retain.
        let block = RcBlock::new(
            move |success: Bool, error: *mut objc2_foundation::NSError| {
                let result = if success.as_bool() {
                    Ok(true)
                } else if error.is_null() {
                    Ok(false)
                } else {
                    // SAFETY: framework passed us a non-null +0 NSError.
                    // Reading `code` is safe for the duration of the block.
                    let code = unsafe { (*error).code() } as i64;
                    Err(code)
                };
                // Receiver may have hung up if we already gave up waiting;
                // ignore that error.
                let _ = tx.send(result);
            },
        );

        // SAFETY:
        // - `ctx` is a valid LAContext we just constructed.
        // - `reason_ns` is a non-null NSString.
        // - `&*block` borrows the heap-allocated block for the duration
        //   of this call; the framework retains it internally before
        //   returning, so its lifetime is independent of ours afterward.
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &reason_ns,
                &block,
            );
        }

        // Block this thread on the reply. The framework normally takes
        // a few seconds at most; we cap with a generous timeout so a
        // wedged dialog can't hang the caller forever.
        match rx.recv_timeout(TOUCH_ID_TIMEOUT) {
            Ok(Ok(true)) => Ok(true),
            Ok(Ok(false)) => Ok(false),
            Ok(Err(code)) => Ok(classify_la_error(code)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                anyhow::bail!("biometric prompt timed out");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("biometric reply channel disconnected");
            }
        }
    }

    /// Map an `LAError` code to a "did the user explicitly say no?"
    /// boolean. User-cancel / fallback / system-cancel all return
    /// `false`; anything else is "couldn't confirm" → also `false`. We
    /// never propagate the underlying code to the user — it's leaked
    /// info that wouldn't help anyway.
    fn classify_la_error(code: i64) -> bool {
        let code = code as i32;
        if code == LAError::UserCancel.0 as i32
            || code == LAError::UserFallback.0 as i32
            || code == LAError::SystemCancel.0 as i32
            || code == LAError::AppCancel.0 as i32
            || code == LAError::AuthenticationFailed.0 as i32
        {
            // Explicit no.
            return false;
        }
        // Anything else (lockout, biometry-not-enrolled, etc.) — also
        // fail closed but log it so the user knows they should re-try
        // with `--no-biometric`.
        tracing::warn!(code, "biometric error code (treating as failure)");
        false
    }
}

/// Trigger a Touch ID prompt with the given reason string. See
/// [`imp::authenticate`] on macOS for semantics.
#[cfg(target_os = "macos")]
pub fn authenticate(reason: &str) -> Result<bool> {
    imp::authenticate(reason)
}

#[cfg(target_os = "linux")]
mod imp {
    //! Linux user-presence gate via polkit.
    //!
    //! We invoke `org.freedesktop.PolicyKit1.Authority.CheckAuthorization`
    //! over the system D-Bus, with a `unix-process` subject describing the
    //! current process (`pid` + `start-time` + `uid`) and the action
    //! `dev.cloak.show-secret`. The `AllowUserInteraction` flag lets the
    //! user's session polkit agent prompt for confirmation.
    //!
    //! Outcomes:
    //! - polkit reports `is_authorized = true`  -> `Ok(true)`
    //! - polkit reports `is_authorized = false`,
    //!   either because the user dismissed/cancelled the prompt
    //!   (`details["polkit.dismissed"]` set) or because no polkit
    //!   authentication agent is registered for this session
    //!   (`is_challenge = true`, no agent picked it up) — both are
    //!   treated as "user presence not confirmed" -> `Ok(false)`.
    //! - the system bus is unreachable or polkit is not running on this
    //!   host -> log a one-shot warning and fail closed with `Ok(false)`.
    //!
    //! No `unsafe`, no syscalls, no shelling out. The `reason` string is
    //! only carried in tracing output; it never contains secret material.
    use anyhow::Result;
    use std::collections::HashMap;
    use zbus::blocking::Connection;
    use zbus_polkit::policykit1::{AuthorityProxyBlocking, CheckAuthorizationFlags, Subject};

    /// Polkit action ID. Must match the `<action id="...">` in
    /// `scripts/polkit/dev.cloak.policy`.
    pub(super) const ACTION_ID: &str = "dev.cloak.show-secret";

    pub fn authenticate(reason: &str) -> Result<bool> {
        // Build the unix-process subject for *this* process. polkit will
        // recheck pid+start-time against /proc to defeat PID-recycle on
        // its end. uid=None lets zbus_polkit fill in the real UID via
        // /proc, which is what polkit expects.
        let subject = match Subject::new_for_owner(std::process::id(), None, None) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    %e,
                    "polkit unavailable, falling back to refusal — pass --no-biometric to bypass"
                );
                return Ok(false);
            }
        };

        // Connect to the system bus (where polkit lives).
        let conn = match Connection::system() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    %e,
                    "polkit unavailable, falling back to refusal — pass --no-biometric to bypass"
                );
                return Ok(false);
            }
        };

        let proxy = match AuthorityProxyBlocking::new(&conn) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    %e,
                    "polkit unavailable, falling back to refusal — pass --no-biometric to bypass"
                );
                return Ok(false);
            }
        };

        // The `details` map can carry `polkit.message` to override the
        // prompt copy in the agent dialog. We pass the caller-supplied
        // reason verbatim — it's a fixed-format human string, not the
        // secret value.
        let mut details: HashMap<&str, &str> = HashMap::new();
        details.insert("polkit.message", reason);

        let result = proxy.check_authorization(
            &subject,
            ACTION_ID,
            &details,
            CheckAuthorizationFlags::AllowUserInteraction.into(),
            "",
        );

        match result {
            Ok(auth) if auth.is_authorized => Ok(true),
            Ok(_auth) => {
                // Either the user dismissed the prompt, no auth agent
                // was registered, or polkit's policy denied us. We do
                // not propagate `auth.details` to the user; treat as
                // "user presence not confirmed".
                Ok(false)
            }
            Err(e) => {
                // Most commonly: the action is not registered (policy
                // file not installed) or polkit itself is not running.
                tracing::warn!(
                    %e,
                    "polkit unavailable, falling back to refusal — pass --no-biometric to bypass"
                );
                Ok(false)
            }
        }
    }
}

/// Trigger a polkit confirmation prompt with the given reason string.
/// See [`imp::authenticate`] on Linux for semantics.
#[cfg(target_os = "linux")]
pub fn authenticate(reason: &str) -> Result<bool> {
    imp::authenticate(reason)
}

/// Stub for targets that aren't macOS or Linux: refuse the reveal so
/// the daemon fails closed. The user can opt out of the biometric
/// gate entirely with `--no-biometric` (CLI flag forwarded to the
/// daemon as the `skip_biometric` field) if they accept the trade-off.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn authenticate(_reason: &str) -> Result<bool> {
    Ok(false)
}

// -------------------------------------------------------------------------
// Test injection hook
// -------------------------------------------------------------------------
//
// Same pattern as `handlers::set_test_sts_factory`: the daemon's
// `vault.show` handler calls [`authenticate`] via
// `current_authenticator()`, which lets integration tests substitute a
// deterministic stub (so we can assert the server-side gate without
// popping a real Touch ID dialog on a developer laptop). Production
// builds compile out the override entirely.

/// Boxed implementation of the biometric prompt — what tests inject in
/// place of [`authenticate`].
#[cfg(any(test, feature = "test-util"))]
pub type Authenticator = std::sync::Arc<dyn Fn(&str) -> Result<bool> + Send + Sync>;

#[cfg(any(test, feature = "test-util"))]
static TEST_AUTHENTICATOR: once_cell::sync::OnceCell<std::sync::Mutex<Option<Authenticator>>> =
    once_cell::sync::OnceCell::new();

/// Install (or remove) a test-only authenticator. Returns the previously
/// installed authenticator, if any. Only available in `cfg(test)` or
/// with the `test-util` feature.
#[cfg(any(test, feature = "test-util"))]
pub fn set_test_authenticator(f: Option<Authenticator>) -> Option<Authenticator> {
    let cell = TEST_AUTHENTICATOR.get_or_init(|| std::sync::Mutex::new(None));
    let mut g = cell.lock().expect("test authenticator lock");
    std::mem::replace(&mut *g, f)
}

#[cfg(any(test, feature = "test-util"))]
fn current_test_authenticator() -> Option<Authenticator> {
    let cell = TEST_AUTHENTICATOR.get_or_init(|| std::sync::Mutex::new(None));
    cell.lock().ok().and_then(|g| g.clone())
}

/// Run the configured biometric prompt. In production this is just
/// [`authenticate`]; under test (or `feature = "test-util"`), an
/// installed override takes precedence so integration tests can assert
/// the server-side gate without an interactive dialog.
pub fn run_authenticate(reason: &str) -> Result<bool> {
    #[cfg(any(test, feature = "test-util"))]
    if let Some(f) = current_test_authenticator() {
        return f(reason);
    }
    authenticate(reason)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! Shape-only tests for the polkit subject we'd send. Real
    //! interaction with polkit is interactive and only runs when
    //! `RUN_POLKIT_TEST=1` is set in the environment, hence `#[ignore]`.

    use super::imp::ACTION_ID;
    use zbus_polkit::policykit1::Subject;

    #[test]
    fn action_id_matches_policy_file() {
        // The Rust-side action ID must match the `<action id="...">`
        // declared in scripts/polkit/dev.cloak.policy. Keep this string
        // pinned — changing it requires repackaging the policy file.
        assert_eq!(ACTION_ID, "dev.cloak.show-secret");
    }

    #[test]
    fn subject_for_current_process_has_required_keys() {
        // `Subject::new_for_owner` populates pid / start-time / uid by
        // reading /proc when the optional args are `None`. /proc is
        // always present on Linux test runners, so this is safe in CI.
        let subject = Subject::new_for_owner(std::process::id(), None, None)
            .expect("subject construction should succeed on Linux with /proc");

        assert_eq!(subject.subject_kind, "unix-process");
        for key in ["pid", "start-time", "uid"] {
            assert!(
                subject.subject_details.contains_key(key),
                "unix-process subject must carry `{key}`",
            );
        }
    }

    /// Real polkit round-trip. Interactive — requires a logged-in
    /// session with a polkit agent and the policy file installed at
    /// `/usr/share/polkit-1/actions/dev.cloak.policy`. Skipped unless
    /// `RUN_POLKIT_TEST=1` is set; even then, `#[ignore]` keeps it out
    /// of the default `cargo test` run.
    #[test]
    #[ignore]
    fn live_polkit_round_trip() {
        if std::env::var_os("RUN_POLKIT_TEST").is_none() {
            eprintln!("skipping: set RUN_POLKIT_TEST=1 to run");
            return;
        }
        let result = super::authenticate("Cloak polkit round-trip test")
            .expect("authenticate() must not return Err on a live system");
        eprintln!("polkit returned: {result}");
    }
}

// Cross-platform unit tests — build everywhere, no syscalls.
#[cfg(test)]
mod cross_tests {
    /// Marker test so `cargo test --workspace` exercises this module on
    /// every platform (even when all interactive paths are gated out).
    /// Real biometric round-trips are interactive and live behind the
    /// `#[ignore]` gates above.
    #[test]
    fn module_is_linkable() {
        // The function is intentionally not invoked here — calling it
        // would pop a Touch ID dialog on a developer laptop. We only
        // assert the module compiles and exposes `authenticate`.
        let _f: fn(&str) -> anyhow::Result<bool> = super::authenticate;
    }
}
