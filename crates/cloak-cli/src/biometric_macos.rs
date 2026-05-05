//! macOS Touch ID authentication via the `LocalAuthentication` framework.
//!
//! `cloak show NAME` calls [`authenticate`] *after* the user has typed
//! their passphrase, as a second factor that the human is physically
//! present at the device. Failure / cancel returns `Ok(false)` so the
//! caller can decide whether to fall back (today: refuse).
//!
//! On non-macOS targets we ship a pure stub that always succeeds — the
//! biometric story on Linux/Windows is a later-week deliverable.

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
        // wedged dialog can't hang the CLI forever.
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
        eprintln!("biometric error code {code} (treating as failure)");
        false
    }
}

/// Trigger a Touch ID prompt with the given reason string. See
/// [`imp::authenticate`] on macOS for semantics.
#[cfg(target_os = "macos")]
pub fn authenticate(reason: &str) -> Result<bool> {
    imp::authenticate(reason)
}

/// Stub for non-macOS targets: always succeeds. Linux / Windows
/// biometric integration is deferred to a later week per the build plan.
#[cfg(not(target_os = "macos"))]
pub fn authenticate(_reason: &str) -> Result<bool> {
    Ok(true)
}
