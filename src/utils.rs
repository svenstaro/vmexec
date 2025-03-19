use std::path::{Path, PathBuf};

use async_walkdir::{Filtering, WalkDir};
use bytesize::ByteSize;
use color_eyre::Result;
use color_eyre::eyre::{Context, OptionExt, bail};
use dir_lock::DirLock;
use directories::ProjectDirs;
use futures::StreamExt;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};
use termion::{color, style};
use tokio::fs::{self, File, create_dir_all, read_to_string};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, info, instrument, trace, warn};

use crate::RUN_DIR_PREFIX;

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
    let lock = DirLock::new(&lock_dir).await?;

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

    trace!("Unlocking {lock_dir:?}");
    lock.drop_async().await?;

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
    let ksm_active = ksm_run.trim() == "1";

    if !ksm_active {
        warn!("Kernel Samepage Merging (KSM) is disabled.");
        warn!("It is strongly recommended to enable it.");
        warn!("You can run `vmexec ksm --enable`");
    }

    Ok(())
}

pub async fn print_ksm_stats() -> Result<()> {
    let pages_scanned = fs::read_to_string("/sys/kernel/mm/ksm/pages_scanned").await?;
    let pages_sharing = fs::read_to_string("/sys/kernel/mm/ksm/pages_sharing").await?;
    let full_scans = fs::read_to_string("/sys/kernel/mm/ksm/full_scans").await?;
    let general_profit = fs::read_to_string("/sys/kernel/mm/ksm/general_profit").await?;
    let general_profit_human = ByteSize::b(general_profit.trim().parse::<u64>()?);

    println!(
        "Pages scanned: {}{}{:>10}{}{}",
        style::Bold,
        color::Fg(color::Blue),
        pages_scanned.trim(),
        color::Fg(color::Reset),
        style::Reset,
    );
    println!(
        "Pages sharing: {}{}{:>10}{}{}",
        style::Bold,
        color::Fg(color::Blue),
        pages_sharing.trim(),
        color::Fg(color::Reset),
        style::Reset,
    );
    println!(
        "Full scans: {}{}{:>13}{}{}",
        style::Bold,
        color::Fg(color::Blue),
        full_scans.trim(),
        color::Fg(color::Reset),
        style::Reset,
    );
    println!(
        "{}General profit: {:>9}{}{}{}",
        style::Bold,
        general_profit_human,
        color::Fg(color::LightBlue),
        color::Fg(color::Reset),
        style::Reset,
    );

    Ok(())
}

/// Check whether the given `pid` is currently an active process
fn pid_exists(pid: usize) -> bool {
    let mut system = sysinfo::System::default();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid.into()]),
        true,
        ProcessRefreshKind::default(),
    ) > 0
}

/// Reap dead runs that didn't get cleaned up
///
/// This can happen is vmexec is killed at a bad moment and doesn't have the opportunity to clean
/// up stuff.
#[instrument]
pub async fn reap_dead_run_dirs(runs_dir: &Path) -> Result<()> {
    let mut entries = fs::read_dir(runs_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let dir = entry.path();
        let dir_name = entry.file_name();

        if dir.is_dir() && dir_name.to_string_lossy().starts_with(RUN_DIR_PREFIX) {
            debug!("Found existing run dir {dir:?}, seeing if we need to clean up");
            let pid_path = dir.join("qemu.pid");

            // Determine if `qemu.pid` exists and try to read its content.
            match File::open(&pid_path).await {
                Ok(mut file) => {
                    let mut pid_str = String::new();
                    file.read_to_string(&mut pid_str)
                        .await
                        .context(format!("Failed to read {pid_path:?}"))?;

                    // Try to parse the pid into usize.
                    if let Ok(pid) = pid_str.trim().parse::<usize>() {
                        if !pid_exists(pid) {
                            // If no process with that pid exists, remove the directory
                            info!("Found dead run dir {dir:?}, cleaning up");
                            fs::remove_dir_all(&dir)
                                .await
                                .context("Failed to remove dead run dir")?;
                        }
                    } else {
                        // Remove the directory if `qemu.pid` is present but invalid.
                        info!("Found run dir {dir:?} with invalid qemu.pid file, cleaning up");
                        fs::remove_dir_all(&dir)
                            .await
                            .context("Failed to remove dead run dir")?;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // If `qemu.pid` does not exist, remove the directory.
                    info!("Found run dir {dir:?} without qemu.pid file, cleaning up");
                    fs::remove_dir_all(&dir)
                        .await
                        .context("Failed to remove dead run dir")?;
                }
                Err(e) => {
                    bail!(e);
                }
            }
        }
    }

    Ok(())
}
