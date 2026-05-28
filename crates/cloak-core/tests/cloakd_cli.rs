use std::process::Command;

#[test]
fn cloakd_version_exits() {
    // The Linux arm64 cross runner can execute the test binary through qemu,
    // but child target binaries do not inherit that runner/sysroot setup.
    if std::env::var_os("CLOAK_SKIP_CHILD_PROCESS_TESTS").is_some() {
        eprintln!("skipping child-process CLI test in emulated cross runner");
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_cloakd"))
        .arg("--version")
        .output()
        .expect("run cloakd --version");

    assert!(
        output.status.success(),
        "cloakd --version failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf8"),
        format!("cloakd {}\n", cloak_core::VERSION)
    );
    assert!(output.stderr.is_empty());
}
