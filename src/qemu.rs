use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use base64ct::Encoding;
use color_eyre::eyre::{bail, Context, Result};
use rustix::{fs::IFlags, io::Errno, path::Arg};
use tokio::{
    fs::{self, File},
    process::{Child, Command},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, trace};

use crate::{cli::BindMount, ExecutablePaths};

/// Get the full command that would be run
pub fn full_cmd(cmd: &Command) -> String {
    let program_str = cmd.as_std().get_program().to_string_lossy();
    let args_str = cmd
        .as_std()
        .get_args()
        .map(|x| x.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{program_str} {args_str}")
}

/// Create an overlay image based on a source image
#[instrument]
pub async fn create_overlay_image(run_data_dir: &Path, source_image: &Path) -> Result<PathBuf> {
    let overlay_image = run_data_dir.join("overlay.qcow2");

    // Touch the file so that it exists.
    let overlay_image_fd = File::create(&overlay_image)
        .await
        .wrap_err("Could't create overlay image")?;

    // Turn off copy-on-write in case the filesystem supports it.
    // This is useful in case this is using a COW-enabled backing filesystem as it will provide no
    // benefit to us here and it will only slow the VM down.
    if let Err(e) = rustix::fs::ioctl_setflags(overlay_image_fd, IFlags::NOCOW) {
        // We'll ignore the error in case it's not supported on the filesystem.
        if e != Errno::NOTSUP {
            return Err(e.into());
        }
    }

    let source_image_str = source_image.to_string_lossy();
    let backing_file = format!("backing_file={source_image_str},backing_fmt=qcow2");
    let mut qemu_img_cmd = Command::new("qemu-img");
    qemu_img_cmd
        .arg("create")
        .args(["-o", &backing_file])
        .args(["-f", "qcow2"])
        .arg(&overlay_image);

    let qemu_img_cmd_str = full_cmd(&qemu_img_cmd);
    info!("Creating overlay image");
    debug!("{qemu_img_cmd_str}");

    let qemu_img_output = qemu_img_cmd.output().await?;
    if !qemu_img_output.status.success() {
        bail!(
            "qemu-img failed: {}",
            String::from_utf8_lossy(&qemu_img_output.stderr)
        );
    }

    Ok(overlay_image)
}

/// Launch an instance of virtiofsd for a particular volume
#[instrument]
pub async fn launch_virtiofsd(
    virtiofsd_path: &Path,
    run_data_dir: &Path,
    volume: &BindMount,
) -> Result<Child> {
    let socket_path = run_data_dir.join(volume.socket_name());
    let mut virtiofsd_cmd = Command::new("unshare");
    virtiofsd_cmd
        .arg("-r")
        .arg("--map-auto")
        .arg("--")
        .arg(virtiofsd_path)
        .args(["--shared-dir", volume.source.as_str()?])
        .args(["--socket-path", socket_path.as_str()?])
        .args(["--sandbox", "chroot"]);

    if volume.read_only {
        virtiofsd_cmd.arg("--readonly");
    }

    let virtiofsd_cmd_str = full_cmd(&virtiofsd_cmd);

    info!("Running virtiofsd for share '{volume}'");
    trace!("{virtiofsd_cmd_str}");

    let mut virtiofsd_child = virtiofsd_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    tokio::select! {
        // I tried very hard to find a reasonable way to check properly for connectivity but there
        // doesn't seem to be a good way as the server quits after the first connection, see also:
        // https://gitlab.com/virtio-fs/virtiofsd/-/issues/62
        // As such, we're going to use a timing based approach for the time being.
        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        _ = virtiofsd_child.wait() => {
            error!("virtiofsd process exited early, that's usually a bad sign");
            let virtiofsd_output = virtiofsd_child.wait_with_output().await?;
            bail!("virtiofsd failed: {}", virtiofsd_output.stderr.to_string_lossy());
        }
    }

    Ok(virtiofsd_child)
}

/// Launch QEMU
#[instrument(skip(
    qemu_cancellation_token,
    ssh_cancellation_token,
    tool_paths,
    show_vm_window,
    ssh_pubkey
))]
pub async fn launch_qemu(
    qemu_cancellation_token: CancellationToken,
    ssh_cancellation_token: CancellationToken,
    run_data_dir: &Path,
    tool_paths: ExecutablePaths,
    volumes: Vec<BindMount>,
    overlay_image: &Path,
    show_vm_window: bool,
    ssh_pubkey: String,
) -> Result<()> {
    let ovmf_vars = run_data_dir.join("OVMF_VARS.4m.fd");
    fs::copy("/usr/share/edk2/x64/OVMF_VARS.4m.fd", &ovmf_vars).await?;

    let overlay_image_str = overlay_image.to_string_lossy();
    let ovmf_vars_str = ovmf_vars.to_string_lossy();

    let sysinfo_system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing()
            .with_cpu(sysinfo::CpuRefreshKind::everything())
            .with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let memory = sysinfo_system.total_memory() / 1024 / 1024 / 1024;
    let logical_core_count = sysinfo_system.cpus().len();

    let ssh_pubkey_base64 = base64ct::Base64::encode_string(ssh_pubkey.as_bytes());

    let mut qemu_cmd = Command::new(tool_paths.qemu_path);
    qemu_cmd
        .args(["-accel", "kvm"])
        .args(["-cpu", "host"])
        .args(["-smp", &logical_core_count.to_string()])

        // SSH port forwarding
        .args(["-nic", "user,model=virtio-net-pci,hostfwd=tcp::2222-:22"])

        // Free Page Reporting allows the guest to signal to the host that memory can be reclaimed.
        .args(["-device", "virtio-balloon,free-page-reporting=on"])

        // Memory configuration
        .args(["-m", &format!("{memory}G")])
        .args(["-object", &format!("memory-backend-memfd,id=mem,size={memory}G,share=on")])
        .args(["-numa", "node,memdev=mem"])

        // UEFI
        .args([
            "-drive",
            "if=pflash,format=raw,unit=0,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd,readonly=on",
        ])
        .args([
            "-drive",
            &format!("if=pflash,format=raw,unit=1,file={ovmf_vars_str}"),
        ])

        // Overlay image
        .args(["-drive", &format!("if=virtio,file={overlay_image_str}")])

        // Here we inject the SSH using systemd.system-credentials, see:
        // https://www.freedesktop.org/software/systemd/man/latest/systemd.system-credentials.html
        .args([
            "-smbios",
            &format!(
                "type=11,value=io.systemd.credential.binary:ssh.authorized_keys.root={ssh_pubkey_base64}"
            ),
        ]);

    // Directory sharing
    let mut virtiofsd_handles = vec![];
    for (i, vol) in volumes.iter().enumerate() {
        let virtiofsd_child = launch_virtiofsd(&tool_paths.virtiofsd_path, run_data_dir, vol)
            .await
            .wrap_err(format!("Failed to launch virtiofsd for {vol}"))?;
        virtiofsd_handles.push(virtiofsd_child);

        let socket_path = run_data_dir.join(vol.socket_name());
        let socket_path_str = socket_path.as_str()?;
        let tag = vol.tag();
        let dest_path = vol.dest.to_string_lossy();
        let read_only = if vol.read_only {
            format!(",ro")
        } else {
            String::new()
        };
        let fstab = format!("{tag} {dest_path} virtiofs defaults{read_only} 0 0");
        let fstab_base64 = base64ct::Base64::encode_string(fstab.as_bytes());
        qemu_cmd
            .args([
                "-chardev",
                &format!("socket,id=char{i},path={socket_path_str}"),
            ])
            .args([
                "-device",
                &format!("vhost-user-fs-pci,chardev=char{i},tag={tag}"),
            ])
            .args([
                "-smbios",
                &format!("type=11,value=io.systemd.credential.binary:fstab.extra={fstab_base64}"),
            ]);
    }

    if !show_vm_window {
        qemu_cmd.arg("-nographic");
    }

    let qemu_cmd_str = full_cmd(&qemu_cmd);
    info!("Running QEMU");
    trace!("{qemu_cmd_str}");

    let qemu_child = qemu_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let qemu_output = tokio::select! {
        _ = qemu_cancellation_token.cancelled() => {
            debug!("QEMU task was cancelled");
            return Ok(());
        }
        val = qemu_child.wait_with_output() => {
            error!("QEMU process exited early, that's usually a bad sign");
            val?
        }
    };

    if !qemu_output.status.success() {
        error!("QEMU failed: {}", qemu_output.stderr.to_string_lossy());
        ssh_cancellation_token.cancel();
    }

    Ok(())
}
