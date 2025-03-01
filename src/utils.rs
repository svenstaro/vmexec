use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io::ErrorKind};

use color_eyre::eyre::{Context, bail};
use color_eyre::{Result, eyre::Error};
use pidfile::PidFile;
use tokio::fs::create_dir_all;
use tokio::process::Command;
use tokio::task::spawn_blocking;
use tracing::{debug, instrument, trace};
use walkdir::WalkDir;

/// Ensure that a required directory exists
pub async fn ensure_directory(purpose: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        debug!("{purpose} dir {path:?} doesn't exist yet, creating");
        create_dir_all(path)
            .await
            .wrap_err(format!("Creating {purpose} dir {path:?}"))?;
    }
    Ok(())
}

/// Path escaping, like `systemd-escape --path`.
///
/// From https://github.com/lucab/libsystemd-rs/blob/b43fa5e3b5eca3e6aa16a6c2fad87220dc0ad7a0/src/unit.rs
pub fn escape_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return "-".to_string();
    }

    let mut slash_seq = false;
    let parts: Vec<String> = trimmed
        .bytes()
        .filter(|b| {
            let is_slash = *b == b'/';
            let res = !(is_slash && slash_seq);
            slash_seq = is_slash;
            res
        })
        .enumerate()
        .map(|(n, b)| escape_byte(b, n))
        .collect();
    parts.join("")
}

fn escape_byte(b: u8, index: usize) -> String {
    let c = char::from(b);
    match c {
        '/' => '-'.to_string(),
        ':' | '_' | '0'..='9' | 'a'..='z' | 'A'..='Z' => c.to_string(),
        '.' if index > 0 => c.to_string(),
        _ => format!(r#"\x{:02x}"#, b),
    }
}

/// Get a random unused CID to use with vsock
///
/// The way this works is that every run dir inside `runs_dir` contains its own CID. We then look
/// at all the CIDs in all run dirs to get the current list of CIDs that are in-use and just pick
/// the next free one.
///
/// This function uses locking so that multiple instances of `vmexec` to not race each other.
#[instrument]
pub async fn create_free_cid(runs_dir: &Path, run_dir: &Path) -> Result<u32> {
    let mut cids = vec![];

    let runs_dir = runs_dir.to_owned();
    let run_dir = run_dir.to_owned();

    let cid: Result<u32, Error> = spawn_blocking(move || {
        let _lockfile = loop {
            std::thread::sleep(Duration::from_millis(100));

            // Lock this operation so other instances of vmexec don't race us for CIDs.
            let lockfile_path = runs_dir.join("pid-lockfile");
            trace!("Trying to lock {lockfile_path:?}");
            match PidFile::new(lockfile_path) {
                Ok(lockfile) => break lockfile,
                Err(ref e) => match e.kind() {
                    // AddrInUse means we're going to have to wait on the lock.
                    ErrorKind::AddrInUse => continue,
                    e => bail!(e),
                },
            };
        };

        for entry in WalkDir::new(&runs_dir).into_iter().filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy();

            if name == "cid" {
                trace!("Found CID file at {:?}", entry.path());
                let cid = fs::read_to_string(entry.path())?;
                cids.push(cid.parse::<u32>()?);
            }
        }

        // Get the next CID.
        cids.sort();
        let cid = if let Some(last_cid) = cids.iter().next_back() {
            last_cid + 1
        } else {
            // We get here if the current list of CIDs is empty. So we'll just start with some
            // arbitrary CID.
            10
        };

        debug!("Our new CID: {cid}");
        fs::write(run_dir.join("cid"), cid.to_string())?;
        Ok(cid)
    })
    .await?;

    cid
}

#[derive(Clone, Debug)]
pub struct ExecutablePaths {
    pub qemu_path: PathBuf,
    pub virtiofsd_path: PathBuf,
    pub virt_copy_out_path: PathBuf,
}

/// Check whether necessary tools are installed and return their paths
pub async fn find_required_tools() -> Result<ExecutablePaths> {
    // Find QEMUU
    let qemu_path = which::which_global("qemu-system-x86_64")
        .wrap_err("Couldn't find qemu-system-x86_64 in PATH")?;

    // Find virtiofsd
    let virtiofsd_path = which::which_in("virtiofsd", Some("/usr/lib:/usr/libexec"), "/")
        .wrap_err("Couldn't find virtiofsd in /usr/lib or /usr/libexec")?;

    // Find virt-copy-out
    let virt_copy_out_path =
        which::which_global("virt-copy-out").wrap_err("Couldn't find virtiofsd in PATH")?;

    // Check whether unshare is working as expected
    let unshare_output = Command::new("unshare")
        .arg("-r")
        .arg("id")
        .kill_on_drop(true)
        .output()
        .await?;
    let unshare_stdout = std::str::from_utf8(&unshare_output.stdout)?;
    let unshare_stderr = std::str::from_utf8(&unshare_output.stderr)?;
    if !unshare_output.status.success() {
        bail!(
            "Test command 'unshare -r id' didn't exit succesfully, stdout: {unshare_stdout}, stderr: {unshare_stderr}"
        );
    }
    if !unshare_stdout.starts_with("uid=0(root) gid=0(root) groups=0(root)") {
        bail!(
            "Expected output to start with 'unshare -r id' to report 'uid=0(root) gid=0(root) groups=0(root)' but got: {unshare_stdout}"
        );
    }

    Ok(ExecutablePaths {
        qemu_path,
        virtiofsd_path,
        virt_copy_out_path,
    })
}
