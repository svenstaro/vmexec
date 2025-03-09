use std::path::{Path, PathBuf};

use async_walkdir::{Filtering, WalkDir};
use color_eyre::Result;
use color_eyre::eyre::{Context, OptionExt, bail};
use dir_lock::DirLock;
use directories::ProjectDirs;
use futures::StreamExt;
use tokio::fs::{self, create_dir_all, read_to_string};
use tokio::process::Command;
use tracing::{debug, instrument, trace, warn};

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

pub struct VmexecDirs {
    pub cache_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub runs_dir: PathBuf,
}

impl VmexecDirs {
    pub async fn new() -> Result<Self> {
        let project_dir =
            ProjectDirs::from("", "", "vmexec").ok_or_eyre("Couldn't get project dir")?;

        // Dir containing cached stuff (usually ~/.config/vmexec/)
        let cache_dir = project_dir.cache_dir().to_path_buf();
        ensure_directory("cache", &cache_dir).await?;

        // Dir containing persistent data (usually ~/.local/share/vmexec/)
        let data_dir = project_dir.data_dir().to_path_buf();
        ensure_directory("data", &data_dir).await?;

        // Dir containing secrets (usually ~/.local/share/vmexec/secrets/)
        let secrets_dir = data_dir.join("secrets");
        ensure_directory("secrets", &secrets_dir).await?;

        // Dir containing all runs (usually ~/.local/share/vmexec/runs/)
        let runs_dir = data_dir.join("runs");
        ensure_directory("runs", &runs_dir).await?;

        Ok(Self {
            cache_dir,
            secrets_dir,
            runs_dir,
        })
    }
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

    let lock_dir = runs_dir.join("lockdir");
    trace!("Trying to lock {lock_dir:?}");
    let _ = DirLock::new(lock_dir).await?;

    let mut entries = WalkDir::new(runs_dir).filter(|entry| async move {
        let filename = entry.file_name();
        if filename.to_string_lossy() == "cid" {
            return Filtering::Continue;
        }
        Filtering::Ignore
    });

    loop {
        match entries.next().await {
            Some(Ok(entry)) => {
                trace!("Found CID file at {:?}", entry.path());
                let cid = fs::read_to_string(entry.path()).await?;
                cids.push(cid.parse::<u32>()?);
            }
            Some(Err(e)) => bail!(e),
            None => break,
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
    fs::write(run_dir.join("cid"), cid.to_string()).await?;
    Ok(cid)
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
    let virt_copy_out_path = which::which_global("virt-copy-out")
        .wrap_err("Couldn't find virt-copy-out (from libguestfs) in PATH")?;

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

pub async fn check_ksm_active() -> Result<()> {
    let ksm_run = read_to_string("/sys/kernel/mm/ksm/run")
        .await
        .wrap_err("Couldn't read /sys/kernel/mm/ksm/run")?;
    let ksm_active = ksm_run == "1";

    if !ksm_active {
        warn!("Kernel Samepage Merging (KSM) is disabled.");
        warn!("It is strongly recommended to enable it.");
        warn!("You can run `vmexec ksm --enable`");
    }

    Ok(())
}
