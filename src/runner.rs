use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use color_eyre::eyre::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument};

use crate::{
    qemu::{QemuLaunchOpts, create_overlay_image, extract_kernel, launch_qemu},
    ssh::{SshLaunchOpts, connect_ssh_for_warmup, connect_ssh_interactive},
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
    run_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<PathBuf> {
    // Before doing anything, first determine whether the image has already been warmed up.
    // We assume that if an overlay image and its extracted kernel exist and will exit early so we
    // don't do any duplicate work.
    let overlay_image_path = qemu_launch_opts.image_path.with_extension("overlay.qcow2");
    if overlay_image_path.exists() {
        debug!("Found existing overlay image at {overlay_image_path:?}");

        if qemu_launch_opts.kernel_initrd.kernel_path.exists()
            && qemu_launch_opts.kernel_initrd.initrd_path.exists()
        {
            debug!("Found extract kernel and initrd, nothing to do for warmup");
            return Ok(overlay_image_path);
        }
    }

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")?.tick_strings(&[
            "▹▹▹▹▹",
            "▸▹▹▹▹",
            "▹▸▹▹▹",
            "▹▹▸▹▹",
            "▹▹▹▸▹",
            "▹▹▹▹▸",
            "▪▪▪▪▪",
        ]),
    );
    progress.enable_steady_tick(Duration::from_millis(100));
    progress.set_message("Warming up image");

    progress.println("Extracting kernel image");
    extract_kernel(&tool_paths.virt_copy_out_path, &qemu_launch_opts.image_path).await?;

    info!("No existing overlay image found, creating...");

    progress.println("Creating overlay image");
    create_overlay_image(&qemu_launch_opts.image_path, &overlay_image_path).await?;

    // Create a new launch struct where we use the overlay image instead of the source image.
    let qemu_launch_opts = QemuLaunchOpts {
        image_path: overlay_image_path.clone(),
        ..qemu_launch_opts.clone()
    };

    // In case of the warmup, we'll poweroff the VM at some point. From that point on, QEMU is
    // expected to exit. If QEMU exit at any other point, it's probably some kind of error.
    // These channels allow us to signal that.
    let qemu_should_exit = Arc::new(AtomicBool::new(false));

    progress.println("Running virtual machine");
    let cancellatation_tokens = CancellationTokens::default();
    let mut joinset = JoinSet::new();
    joinset.spawn({
        let qemu_should_exit = qemu_should_exit.clone();
        let run_dir = run_dir.to_owned();
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move {
            launch_qemu(
                cancellatation_tokens_,
                qemu_should_exit,
                run_dir.as_path(),
                tool_paths,
                qemu_launch_opts,
            )
            .await
        }
    });
    connect_ssh_for_warmup(qemu_should_exit, ssh_launch_opts)
        .await
        .wrap_err("SSH connection error")?;

    while let Some(res) = joinset.join_next().await {
        res??
    }

    progress.finish_with_message("Image is warmed up");

    Ok(overlay_image_path)
}

/// Run a user-supplied command in a throw-away VM
#[instrument]
pub async fn run_command(
    run_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<()> {
    let cancellatation_tokens = CancellationTokens::default();
    let mut joinset = JoinSet::new();
    joinset.spawn({
        let run_data_dir = run_dir.to_owned();
        let cancellatation_tokens_ = cancellatation_tokens.clone();
        async move {
            launch_qemu(
                cancellatation_tokens_,
                Arc::new(AtomicBool::new(false)),
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
