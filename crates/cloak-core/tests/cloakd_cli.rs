use std::process::Command;

#[test]
fn cloakd_version_exits() {
    let output = Command::new(env!("CARGO_BIN_EXE_cloakd"))
        .arg("--version")
        .output()
        .expect("run cloakd --version");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf8"),
        format!("cloakd {}\n", cloak_core::VERSION)
    );
    assert!(output.stderr.is_empty());
}
