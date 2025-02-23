use std::path::PathBuf;

use clap::{crate_name, CommandFactory, Parser};
use color_eyre::eyre::{bail, Context, OptionExt, Result};
use directories::ProjectDirs;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, Level};

mod cli;
mod qemu;
mod ssh;
mod utils;
mod vm_images;

use crate::qemu::{create_overlay_image, launch_qemu};
use crate::ssh::{connect_ssh, create_ssh_key};
use crate::utils::create_free_cid;
use crate::vm_images::ensure_archlinux_image;

fn install_tracing(log_level: Level) {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer().with_target(false);
    let filter_layer = EnvFilter::try_new(format!("{}={}", crate_name!(), log_level)).unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();
}

#[derive(Debug)]
pub struct ExecutablePaths {
    pub qemu_path: PathBuf,
    pub virtiofsd_path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct CancellationTokens {
    pub qemu: CancellationToken,
    pub ssh: CancellationToken,
}

/// Check whether necessary tools are installed and return their paths
async fn find_required_tools() -> Result<ExecutablePaths> {
    // Find QEMUU
    let qemu_path = which::which_global("qemu-system-x86_64")
        .wrap_err("Couldn't find qemu-system-x86_64 in PATH")?;

    // Find virtiofsd
    let virtiofsd_path = which::which_in("virtiofsd", Some("/usr/lib:/usr/libexec"), "/")
        .wrap_err("Couldn't find virtiofsd in /usr/lib or /usr/libexec")?;

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
        bail!("Expected output to start with 'unshare -r id' to report 'uid=0(root) gid=0(root) groups=0(root)' but got: {unshare_stdout}");
    }

    Ok(ExecutablePaths {
        qemu_path,
        virtiofsd_path,
    })
}

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    install_tracing(cli.log_level);
    color_eyre::install()?;

    if let Some(shell) = cli.print_completions {
        let mut clap_app = cli::Cli::command();
        let app_name = clap_app.get_name().to_string();
        clap_complete::generate(shell, &mut clap_app, app_name, &mut std::io::stdout());
        return Ok(());
    }

    if cli.print_manpage {
        let clap_app = cli::Cli::command();
        let man = clap_mangen::Man::new(clap_app);
        man.render(&mut std::io::stdout())?;
        return Ok(());
    }

    // Make sure the tools we need are actually installed.
    let tool_paths = find_required_tools().await?;

    let project_dir = ProjectDirs::from("", "", "vmexec").ok_or_eyre("Couldn't get project dir")?;
    let cache_dir = project_dir.cache_dir();
    if !cache_dir.exists() {
        debug!("Cache dir {cache_dir:?} doesn't exist yet, creating");
        std::fs::create_dir_all(cache_dir).wrap_err(format!("Creating cache dir {cache_dir:?}"))?;
    }

    let data_dir = project_dir.data_dir();
    if !data_dir.exists() {
        debug!("Data dir {data_dir:?} doesn't exist yet, creating");
        std::fs::create_dir_all(data_dir).wrap_err(format!("Creating data dir {data_dir:?}"))?;
    }

    // The data dir for the actual run should be temporary and self-deleting so we don't end up
    // with a lot of garbage after some time.
    let run_data_dir = TempDir::with_prefix_in("run-", data_dir)
        .wrap_err("Couldn't make temp dir in {data_dir}")?;
    debug!("run data dir is: {:?}", run_data_dir.path());

    // We need a free CID for host-guest communication via vsock.
    let cid = create_free_cid(data_dir, run_data_dir.path()).await?;

    let image = if let Some(os) = cli.image_source.os {
        match os {
            cli::OsType::Archlinux => ensure_archlinux_image(cache_dir, cli.pull).await?,
        }
    } else if let Some(image) = cli.image_source.image {
        image
    } else {
        unreachable!();
    };

    let ssh_keypair = create_ssh_key(run_data_dir.path()).await?;
    let overlay_image = create_overlay_image(run_data_dir.path(), &image).await?;
    let qemu_launch_opts = qemu::QemuLaunchOpts {
        volumes: cli.volumes,
        overlay_image,
        show_vm_window: cli.show_vm_window,
        ssh_pubkey: ssh_keypair.pubkey_str,
        cid,
    };

    debug!("SSH command for manual debugging:");
    debug!("ssh root@vsock/{cid} -i {privkey_path:?} -F /dev/null -o StrictHostKeyChecking=off -o UserKNownHostsFile=/dev/null", privkey_path=ssh_keypair.privkey_path);

    let cancellatation_tokens = CancellationTokens::default();

    let mut joinset = JoinSet::new();

    joinset.spawn({
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move {
            launch_qemu(
                cancellatation_tokens_,
                run_data_dir.path(),
                tool_paths,
                qemu_launch_opts,
            )
            .await
        }
    });
    joinset.spawn({
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move {
            connect_ssh(
                cancellatation_tokens_,
                ssh_keypair.privkey_str,
                cli.ssh_timeout,
                cid,
                cli.env,
                cli.args,
            )
            .await
        }
    });

    while let Some(res) = joinset.join_next().await {
        res??
    }

    Ok(())
}
