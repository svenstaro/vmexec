use std::path::Path;

use color_eyre::eyre::{Context, Result};
use qcow2_rs::meta::Qcow2Header;
use tokio::{fs::File, io::AsyncReadExt, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument};

use crate::{
    qemu::{create_overlay_image, launch_qemu, QemuLaunchOpts},
    ssh::{connect_ssh, connect_ssh_interactive, SshLaunchOpts},
    utils::ExecutablePaths,
};

#[derive(Debug, Clone, Default)]
pub struct CancellationTokens {
    pub qemu: CancellationToken,
    pub ssh: CancellationToken,
}

/// Make sure the VM is warmed up
///
/// This will:
/// 1. Extract the kernel and initrd from the image's boot partition so we can boot more quickly
///    without going through the bootloader
/// 2. Create an overlay image with the supplied image as a backing file
/// 3. Spin up the supplied VM
/// 4. Wait until it is connectable via SSH
/// 5. Wait until a readiness condition is met
/// 6. Stop it
#[instrument(skip(tool_paths, qemu_launch_opts, ssh_launch_opts))]
pub async fn run_warmup(
    run_data_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<()> {
    // Before doing anything, first determine whether the image has already been warmed up.
    // We assume that if an overlay image exists AND it has a snapshot that it has been warmed up
    // and will exit early so we don't do any duplicate work.
    let overlay_image_path = qemu_launch_opts.image.with_extension("overlay.qcow2");
    if overlay_image_path.exists() {
        debug!("Found existing overlay image candidate at {overlay_image_path:?}, checking whether it has snapshots");
        let mut qcow2_file = File::open(&overlay_image_path).await?;
        let mut buf = vec![0_u8; 4096];
        let _ = qcow2_file.read(&mut buf).await?;
        let qcow2_header = Qcow2Header::from_buf(&buf)?;
        if qcow2_header.nb_snapshots() >= 1 {
            debug!("Found existing overlay image with a snapshot at {overlay_image_path:?}, assuming this is the warmed up overlay image");
            return Ok(());
        }
    }

    info!("No existing overlay image with warmed up snapshot found, creating...");

    create_overlay_image(&qemu_launch_opts.image, &overlay_image_path).await?;

    let qemu_launch_opts = QemuLaunchOpts {
        image: overlay_image_path,
        ..qemu_launch_opts
    };

    let cancellatation_tokens = CancellationTokens::default();
    let mut joinset = JoinSet::new();
    joinset.spawn({
        let run_data_dir = run_data_dir.to_owned();
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move {
            launch_qemu(
                cancellatation_tokens_,
                run_data_dir.as_path(),
                tool_paths,
                qemu_launch_opts,
            )
            .await
        }
    });
    connect_ssh(ssh_launch_opts)
        .await
        .wrap_err("SSH connection error")?;

    cancellatation_tokens.qemu.cancel();
    while let Some(res) = joinset.join_next().await {
        res??
    }

    Ok(())
}

/// Run a user-supplied command in a throw-away VM
#[instrument]
pub async fn run_command(
    run_data_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<()> {
    let overlay_image = qemu_launch_opts.image.with_extension("overlay.qcow2");

    let qemu_launch_opts = QemuLaunchOpts {
        image: overlay_image,
        ..qemu_launch_opts
    };

    let cancellatation_tokens = CancellationTokens::default();
    let mut joinset = JoinSet::new();
    joinset.spawn({
        let run_data_dir = run_data_dir.to_owned();
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move {
            launch_qemu(
                cancellatation_tokens_,
                run_data_dir.as_path(),
                tool_paths,
                qemu_launch_opts,
            )
            .await
        }
    });
    joinset.spawn({
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move { connect_ssh_interactive(cancellatation_tokens_, ssh_launch_opts).await }
    });

    while let Some(res) = joinset.join_next().await {
        res??
    }

    Ok(())
}
