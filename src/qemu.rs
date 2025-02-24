use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use base64ct::{Base64, Encoding};
use color_eyre::eyre::{bail, Context, Result};
use qapi::futures::QmpStreamTokio;
use tokio::process::{Child, Command};
use tracing::{debug, error, info, instrument, trace};

use crate::{cli::BindMount, runner::CancellationTokens, utils::ExecutablePaths};

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

/// Convert OVMF UEFI variables raw image to qcow2
///
/// We need it to be qcow2 so that snapshotting will work. We don't particularly want to snaphot
/// the UEFI variables, however, snapshotting the VM only works if all its writeable disks support
/// it so here we are.
#[instrument]
pub async fn convert_ovmf_uefi_variables(
    run_data_dir: &Path,
    source_image: &Path,
) -> Result<PathBuf> {
    let output_file = run_data_dir.join("OVMF_VARS.4m.fd.qcow2");

    let mut qemu_img_cmd = Command::new("qemu-img");
    qemu_img_cmd
        .arg("convert")
        .args(["-O", "qcow2"])
        .arg(source_image)
        .arg(&output_file);

    let qemu_img_cmd_str = full_cmd(&qemu_img_cmd);
    info!("Converting OVMF UEFI vars file to qcow2");
    debug!("{qemu_img_cmd_str}");

    let qemu_img_output = qemu_img_cmd.output().await?;
    if !qemu_img_output.status.success() {
        bail!(
            "qemu-img convert failed: {}",
            String::from_utf8_lossy(&qemu_img_output.stderr)
        );
    }

    Ok(output_file)
}

/// Create an overlay image based on a source image
#[instrument]
pub async fn create_overlay_image(source_image: &Path, overlay_image: &Path) -> Result<()> {
    let overlay_image = source_image.with_extension("overlay.qcow2");

    let source_image_str = source_image.to_string_lossy();
    let backing_file = format!("backing_file={source_image_str},backing_fmt=qcow2,nocow=on");
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
            "qemu-img create failed: {}",
            String::from_utf8_lossy(&qemu_img_output.stderr)
        );
    }

    Ok(())
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
        .args(["--shared-dir", &volume.source.to_string_lossy()])
        .args(["--socket-path", &socket_path.to_string_lossy()])
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
            bail!("virtiofsd failed: {}", String::from_utf8(virtiofsd_output.stderr)?);
        }
    }

    Ok(virtiofsd_child)
}

#[derive(Debug, Clone)]
pub struct QemuLaunchOpts {
    pub volumes: Vec<BindMount>,
    pub image: PathBuf,
    pub show_vm_window: bool,
    pub pubkey: String,
    pub cid: u32,
}

/// Launch QEMU
#[instrument(skip(cancellation_tokens, tool_paths, qemu_launch_opts))]
pub async fn launch_qemu(
    cancellation_tokens: CancellationTokens,
    run_data_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
    loadvm: bool,
) -> Result<()> {
    let ovmf_vars_system_path = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.fd");
    //let ovmf_vars = convert_ovmf_uefi_variables(run_data_dir, ovmf_vars_system_path).await?;

    let overlay_image_str = qemu_launch_opts.image.to_string_lossy();
    //let ovmf_vars_str = ovmf_vars.to_string_lossy();
    let ovmf_vars_str = ovmf_vars_system_path.to_string_lossy();

    let sysinfo_system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing()
            .with_cpu(sysinfo::CpuRefreshKind::everything())
            .with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let memory = sysinfo_system.total_memory() / 1024 / 1024 / 1024;
    let logical_core_count = sysinfo_system.cpus().len();

    let ssh_pubkey_base64 = Base64::encode_string(qemu_launch_opts.pubkey.as_bytes());

    let sshd_dropin = "[Service]\nExecStart=\nExecStart=/usr/bin/sshd -D -o 'AcceptEnv *'\n";
    let sshd_dropin_base64 = Base64::encode_string(sshd_dropin.as_bytes());
    let cid = qemu_launch_opts.cid;

    let qmp_socket_path = run_data_dir.join("qmp.sock,server,wait=off");
    let qmp_socket_path_str = qmp_socket_path.to_string_lossy();

    let mut qemu_cmd = Command::new(tool_paths.qemu_path);
    qemu_cmd
        .args(["-accel", "kvm"])
        .args(["-cpu", "host"])
        .args(["-smp", &logical_core_count.to_string()])

        // SSH port forwarding
        .args(["-device", &format!("vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={cid}")])

        // Network controller
        // TODO In theory this should be faster but I noticed that it actually takes quite a bit
        // longer to connect.
        //.args(["-nic", "user,model=virtio"])
        //.args(["-net", "nic,model=virtio"])

        // Free Page Reporting allows the guest to signal to the host that memory can be reclaimed.
        .args(["-device", "virtio-balloon,free-page-reporting=on"])

        // Memory configuration
        .args(["-m", &format!("2G,slots=2,maxmem={memory}G")])
        .args(["-object", &format!("memory-backend-memfd,id=mem,merge=on,size=2G,share=on")])
        .args(["-numa", "node,memdev=mem"])

        // UEFI
        .args([
            "-drive",
            "if=pflash,format=raw,unit=0,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd,readonly=on",
        ])
        .args([
            "-drive",
            &format!("if=pflash,node-name=efi-vars,format=raw,unit=1,file={ovmf_vars_str},readonly=on"),
        ])

        // Overlay image
        .args(["-drive", &format!("if=virtio,node-name=overlay-disk,file={overlay_image_str}")])


        // Here we inject the SSH using systemd.system-credentials, see:
        // https://www.freedesktop.org/software/systemd/man/latest/systemd.system-credentials.html
        .args([
            "-smbios",
            &format!(
                "type=11,value=io.systemd.credential.binary:ssh.authorized_keys.root={ssh_pubkey_base64}"
            ),
        ])

        // Allow setting arbitrary environment variables.
        .args([
            "-smbios",
            &format!(
                "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.sshd.service={sshd_dropin_base64}"
            ),
        ]);

    if loadvm {
        qemu_cmd.args(["-loadvm", "warmup"]);
    }

    if !loadvm {
        // QMP API to expose QEMU command API
        qemu_cmd.args(["-qmp", &format!("unix:{qmp_socket_path_str}")]);
    }
    // Directory sharing
    //let mut virtiofsd_handles = vec![];
    //for (i, vol) in qemu_launch_opts.volumes.iter().enumerate() {
    //    let virtiofsd_child = launch_virtiofsd(&tool_paths.virtiofsd_path, run_data_dir, vol)
    //        .await
    //        .wrap_err(format!("Failed to launch virtiofsd for {vol}"))?;
    //    virtiofsd_handles.push(virtiofsd_child);
    //
    //    let socket_path = run_data_dir.join(vol.socket_name());
    //    let socket_path_str = socket_path.to_string_lossy();
    //    let tag = vol.tag();
    //    let dest_path = vol.dest.to_string_lossy();
    //    let read_only = if vol.read_only {
    //        String::from(",ro")
    //    } else {
    //        String::new()
    //    };
    //    let fstab = format!("{tag} {dest_path} virtiofs defaults{read_only} 0 0");
    //    let fstab_base64 = Base64::encode_string(fstab.as_bytes());
    //    qemu_cmd
    //        .args([
    //            "-chardev",
    //            &format!("socket,id=char{i},path={socket_path_str}"),
    //        ])
    //        .args([
    //            "-device",
    //            &format!("vhost-user-fs-pci,chardev=char{i},tag={tag}"),
    //        ])
    //        .args([
    //            "-smbios",
    //            &format!("type=11,value=io.systemd.credential.binary:fstab.extra={fstab_base64}"),
    //        ]);
    //}

    if !qemu_launch_opts.show_vm_window {
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
        _ = cancellation_tokens.qemu.cancelled() => {
            debug!("QEMU task was cancelled");
            return Ok(());
        }
        val = qemu_child.wait_with_output() => {
            error!("QEMU process exited early, that's usually a bad sign");
            val?
        }
    };

    if !qemu_output.status.success() {
        error!("QEMU failed: {}", String::from_utf8(qemu_output.stderr)?);
        cancellation_tokens.ssh.cancel();
    }

    Ok(())
}

/// Take a snapshot of a QEMU VM via QMP API
#[instrument]
pub async fn take_snapshot(run_data_dir: &Path) -> Result<()> {
    info!("Taking snapshot");
    let qmp_socket_path = run_data_dir.join("qmp.sock");

    let stream = QmpStreamTokio::open_uds(&qmp_socket_path)
        .await
        .wrap_err(format!(
            "Couldn't open QEMU QMP socket at {qmp_socket_path:?}"
        ))?;
    let mut stream = stream
        .negotiate()
        .await
        .wrap_err("QMP stream negotiation failed")?;

    stream
        .execute(qapi::qmp::snapshot_save {
            job_id: "snapshot".to_string(),
            tag: "warmup".to_string(),
            devices: vec!["overlay-disk".to_string()],
            //devices: vec!["overlay-disk".to_string(), "efi-vars".to_string()],
            vmstate: "overlay-disk".to_string(),
        })
        .await
        .wrap_err("QMP command executation faile")?;

    let jobs = stream
        .execute(qapi::qmp::query_jobs {})
        .await
        .wrap_err("QMP command executation faile")?;

    if let Some(job) = jobs.iter().find(|j| j.id == "snapshot") {
        if let Some(err) = &job.error {
            bail!("Snapshotting failed somehow: {err}");
        }
    }

    trace!("{jobs:#?}");

    Ok(())
}
