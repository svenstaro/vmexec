use clap::{crate_name, CommandFactory, Parser};
use color_eyre::eyre::{Context, OptionExt, Result};
use directories::ProjectDirs;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, Level};

mod cli;
mod qemu;
mod ssh;
mod vm_images;

use crate::qemu::{create_overlay_image, launch_qemu};
use crate::ssh::{connect_ssh, create_ssh_key};
use crate::vm_images::download_archlinux;

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

    let project_dir = ProjectDirs::from("", "", "vmexec").ok_or_eyre("Couldn't get project dir")?;
    let cache_dir = project_dir.cache_dir();
    if !cache_dir.exists() {
        debug!("Cache dir {cache_dir:?} didn't exist yet, creating");
        std::fs::create_dir_all(cache_dir).wrap_err(format!("Creating cache dir {cache_dir:?}"))?;
    }

    let data_dir = project_dir.data_dir();
    if !data_dir.exists() {
        debug!("Data dir {data_dir:?} didn't exist yet, creating");
        std::fs::create_dir_all(&data_dir).wrap_err(format!("Creating cache dir {data_dir:?}"))?;
    }

    // The data dir for the actual run should be temporary and self-deleting so we don't end up
    // with a lot of garbage after some time.
    let run_data_dir = TempDir::with_prefix_in("run-", data_dir)
        .wrap_err("Couldn't make temp dir in {data_dir}")?;

    let image = if let Some(os) = cli.image_source.os {
        match os {
            cli::OsType::Archlinux => download_archlinux(cli.pull, cache_dir).await?,
        }
    } else if let Some(image) = cli.image_source.image {
        image
    } else {
        unreachable!();
    };

    let ssh_keypair = create_ssh_key(run_data_dir.path()).await?;
    let overlay_image = create_overlay_image(run_data_dir.path(), &image).await?;

    debug!("SSH command for manual debugging:");
    debug!("ssh root@localhost -p 2222 -i {privkey_path:?} -F /dev/null -o StrictHostKeyChecking=off -o UserKNownHostsFile=/dev/null", privkey_path=ssh_keypair.privkey_path);

    let qemu_cancellation_token = CancellationToken::new();
    let ssh_cancellation_token = CancellationToken::new();

    let qemu_task = tokio::spawn({
        let qemu_cancellation_token_ = qemu_cancellation_token.clone();
        let ssh_cancellation_token_ = ssh_cancellation_token.clone();
        async move {
            launch_qemu(
                qemu_cancellation_token_,
                ssh_cancellation_token_,
                run_data_dir.path(),
                &overlay_image,
                cli.show_vm_window,
                ssh_keypair.pubkey_str,
            )
            .await
        }
    });
    let ssh_task = tokio::spawn({
        let qemu_cancellation_token_ = qemu_cancellation_token.clone();
        let ssh_cancellation_token_ = ssh_cancellation_token.clone();
        async move {
            connect_ssh(
                qemu_cancellation_token_,
                ssh_cancellation_token_,
                ssh_keypair.privkey_str,
                cli.ssh_timeout,
                cli.args,
            )
            .await
        }
    });

    // If we get here, we're probably done with SSH as the VM is running forever.
    // As such, we'll need to try to clean up the VM here.
    let _ = tokio::join!(qemu_task, ssh_task);
    debug!("Finished running QEMU and SSH tasks");

    Ok(())
}
