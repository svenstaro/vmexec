use std::time::Duration;

use clap::{crate_name, CommandFactory, Parser};
use color_eyre::eyre::{Context, OptionExt, Result};
use directories::ProjectDirs;
use tempfile::TempDir;
use tracing::{debug, instrument, Level};

mod cli;
mod qemu;
mod runner;
mod ssh;
mod utils;
mod vm_images;

use crate::runner::{run_command, run_warmup};
use crate::ssh::create_ssh_key;
use crate::utils::{create_free_cid, find_required_tools};
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

    let qemu_launch_opts = qemu::QemuLaunchOpts {
        volumes: cli.volumes,
        image,
        show_vm_window: cli.show_vm_window,
        pubkey: ssh_keypair.pubkey_str,
        cid,
    };

    let ssh_launch_opts = ssh::SshLaunchOpts {
        timeout: cli.ssh_timeout,
        env_vars: cli.env,
        args: cli.args,
        privkey: ssh_keypair.privkey_str,
        cid,
    };

    run_warmup(
        run_data_dir.path(),
        tool_paths.clone(),
        qemu_launch_opts.clone(),
        ssh_launch_opts.clone(),
    )
    .await?;

    tokio::time::sleep(Duration::from_secs(5)).await;

    debug!("SSH command for manual debugging:");
    debug!(
        "ssh root@vsock/{cid} -i {privkey_path:?}",
        privkey_path = ssh_keypair.privkey_path
    );
    run_command(
        run_data_dir.path(),
        tool_paths,
        qemu_launch_opts,
        ssh_launch_opts,
    )
    .await?;

    Ok(())
}
