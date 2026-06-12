//! `cloak daemon-unlock` — push the vault passphrase into the running
//! daemon so MCP peers can serve `vault.list` / `tool.*` requests.
//!
//! ## Why this exists
//!
//! In v0.1 the CLI is a *library client* of `cloak-core`: every
//! `cloak {init,add,set,get,list,rm,show,status}` opens the SQLite vault
//! file directly. The privileged daemon (`cloakd`) keeps its own
//! in-memory `Vault`, which starts **locked**. MCP peers can only call
//! the daemon, so until somebody unlocks the daemon's in-memory state,
//! the model surface returns `vault-locked`.
//!
//! `cloak daemon-unlock` is the smallest possible bridge: it speaks
//! the IPC protocol as a CLI peer, performs `cli.handshake`, and then
//! forwards a `vault.unlock` with the user's passphrase. Once the
//! daemon's vault is unlocked, MCP requests can flow.
//!
//! In v1.x the CLI will move *fully* onto IPC and this command will
//! become an internal detail of `cloak unlock`. For v0.1 it's a
//! deliberately separate step so the smoke test can demonstrate the
//! end-to-end flow without conflating "open the file on disk" with
//! "tell the daemon the passphrase".

use anyhow::Result;
use serde_json::json;

use crate::commands::daemon_ipc::call_daemon;
use crate::commands::Context;
use crate::prompt;

pub fn run(_ctx: &Context) -> Result<()> {
    // Read passphrase (env override honored by `prompt`).
    let pass = prompt::prompt_passphrase("vault passphrase: ")?;

    // Hand off to the shared IPC helper: it resolves the socket, runs the
    // socket-safety + peer-credential checks, handshakes, and forwards the
    // unlock. The security posture is identical to the inline version this
    // replaced.
    call_daemon(
        "vault.unlock",
        json!({ "passphrase": pass.expose_secret() }),
    )?;
    println!("daemon vault unlocked");
    Ok(())
}
