use anyhow::Result;
use clap::{crate_name, CommandFactory, Parser};
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, Level};

mod cli;
mod qemu;
mod ssh;
mod vm_images;

use crate::cli::DefaultOrExplicitTempDir;
use crate::qemu::{create_overlay_image, launch_qemu};
use crate::ssh::{connect_ssh, create_ssh_key};
use crate::vm_images::download_archlinux;

fn setup_tracing(log_level: Level) -> Result<()> {
    match log_level {
        tracing::Level::TRACE => tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(format!("{}=trace", crate_name!()))
            .init(),
        tracing::Level::DEBUG => tracing_subscriber::fmt()
            .without_time()
            .pretty()
            .with_env_filter(format!("{}=debug", crate_name!()))
            .init(),
        tracing::Level::INFO => tracing_subscriber::fmt()
            .without_time()
            .pretty()
            .with_env_filter(format!("{}=info", crate_name!()))
            .init(),
        tracing::Level::WARN => tracing_subscriber::fmt()
            .without_time()
            .compact()
            .with_env_filter(format!("{}=warn", crate_name!()))
            .init(),
        tracing::Level::ERROR => tracing_subscriber::fmt()
            .without_time()
            .compact()
            .with_env_filter(format!("{}=error", crate_name!()))
            .init(),
    };

    Ok(())
}

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    setup_tracing(cli.log_level)?;

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

    let tmpdir = if let Some(tmpdir) = cli.tmpdir {
        DefaultOrExplicitTempDir::ExplicitTempDir(tmpdir)
    } else {
        DefaultOrExplicitTempDir::DefaultTempDir(tempfile::tempdir()?)
    };

    let image = if let Some(os) = cli.image_source.os {
        match os {
            cli::OsType::Archlinux => {
                download_archlinux(&tmpdir).await?;
                std::path::PathBuf::new()
            }
        }
    } else if let Some(image) = cli.image_source.image {
        image
    } else {
        unreachable!();
    };

    let ssh_keypair = create_ssh_key(&tmpdir).await?;
    let overlay_image = create_overlay_image(&tmpdir, &image).await?;

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
                &tmpdir,
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
