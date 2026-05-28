//! Guardrails for env vars that exist only to make CLI integration
//! tests deterministic.

use anyhow::Result;
use std::env::VarError;

/// Required opt-in before any test-only env var is honored.
pub const UNSAFE_TEST_MODE_ENV: &str = "CLOAK_UNSAFE_TEST_MODE";

/// Return whether the explicit unsafe test-mode guard is enabled.
pub fn enabled() -> bool {
    std::env::var(UNSAFE_TEST_MODE_ENV)
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
}

/// Read a test-only env var. If it is set without the unsafe guard,
/// fail closed instead of silently changing normal CLI behavior.
pub fn env_var(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) if enabled() => Ok(Some(value)),
        Ok(_) => anyhow::bail!(
            "{name} is a test-only environment variable; set {UNSAFE_TEST_MODE_ENV}=1 only in tests, or unset {name}"
        ),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8"),
    }
}

/// Read a boolean-ish test-only env var.
pub fn env_flag(name: &str) -> Result<bool> {
    Ok(env_var(name)?.is_some_and(|v| {
        v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
    }))
}
