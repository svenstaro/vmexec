use std::fmt::Write;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64ct::{Base64, Encoding};
use color_eyre::eyre::{Context, OptionExt, Result, bail};
use tokio::process::{Child, Command};
use tracing::{debug, error, info, instrument, trace};

use crate::cli::PmemMount;
use crate::{
    cli::{BindMount, PublishPort},
    runner::CancellationTokens,
    utils::ExecutablePaths,
};

// Kernel and initrd paths
#[derive(Debug, Clone)]
pub struct KernelInitrd {
    pub kernel_path: PathBuf,
    pub initrd_path: PathBuf,
}

/// Get the full command that would be run
pub fn full_cmd(cmd: &Command) -> String {
    let program_str = cmd.as_std().get_program().to_string_lossy();
    let args_str = cmd
        .as_std()
        .get_args()
        .map(|x| x.to_string_lossy())
        .map(|x| {
            // Make sure that commands that contain spaces will be properly quoted.
            if x.contains(' ') {
                format!("\"{x}\"")
            } else {
                format!("{x}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("{program_str} {args_str}")
}

/// Extract the kernel and initrd from a given image
///
/// It will extract it into the same dir of the `image_path`.
pub async fn extract_kernel(virt_copy_out_path: &Path, image_path: &Path) -> Result<()> {
    let dest_dir = image_path
        .parent()
        .ok_or_eyre("Image {image_path:?} doesn't have a parent")?;
    let mut virt_copy_out_cmd = Command::new(virt_copy_out_path);
    virt_copy_out_cmd
        .args(["-a", &image_path.to_string_lossy()])
        .args(["/boot/initramfs-linux.img", "/boot/vmlinuz-linux"])
        .arg(dest_dir);

    let virt_copy_out_cmd_str = full_cmd(&virt_copy_out_cmd);
    info!("Extracting kernel from {image_path:?}");
    debug!("{virt_copy_out_cmd_str}");

    let virt_copy_out_output = virt_copy_out_cmd.output().await?;
    if !virt_copy_out_output.status.success() {
        bail!(
            "virt_copy_out failed: {}",
            String::from_utf8_lossy(&virt_copy_out_output.stderr)
        );
    }

    Ok(())
}

/// Convert OVMF UEFI variables raw image to qcow2
///
/// We need it to be qcow2 so that snapshotting will work. We don't particularly want to snaphot
/// the UEFI variables, however, snapshotting the VM only works if all its writeable disks support
/// it so here we are.
///
/// Also, if we don't provide a read-write OVMF_VARS file on boot, we'll get an `NvVars` file in
/// our writeable mounts which is what QEMU uses to emulate writeable UEFI vars.
#[instrument]
pub async fn convert_ovmf_uefi_variables(run_dir: &Path, source_image: &Path) -> Result<PathBuf> {
    let output_file = run_dir.join("OVMF_VARS.4m.fd.qcow2");

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
    run_dir: &Path,
    volume: &BindMount,
) -> Result<Child> {
    let socket_path = run_dir.join(volume.socket_name());
    let mut virtiofsd_cmd = Command::new("unshare");
    virtiofsd_cmd
        .arg("-r")
        .arg("--map-auto")
        .arg("--")
        .arg(virtiofsd_path)
        .args(["--shared-dir", &volume.source.to_string_lossy()])
        .args(["--socket-path", &socket_path.to_string_lossy()])
        // This seems to allow us to skip past the guest's page cache which is very desireable
        // since we want to ensure that the memory usage inside the guest stays minimal. If we
        // instead hit the host directly then the host can manage the cache for us.
        .args(["--cache", "never"])
        // Like the above, we want to skip the caches as much as possible. so allowing direct IO
        // seems prudent.
        .arg("--allow-direct-io")
        // It seems like a good idea to allow mmap to work so that users are not suprised by weird
        // kernel errors.
        .arg("--allow-mmap")
        // Create a thread pool with 8 threads. We have yet to test whether this does anything in
        // terms of performance.
        .args(["--thread-pool-size", "8"])
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
        _ = tokio::time::sleep(Duration::from_millis(250)) => {},
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
    pub pmems: Vec<PmemMount>,
    pub published_ports: Vec<PublishPort>,
    pub image_path: PathBuf,
    pub ovmf_uefi_vars_path: PathBuf,
    pub kernel_initrd: KernelInitrd,
    pub show_vm_window: bool,
    pub pubkey: String,
    pub cid: u32,
    pub is_warmup: bool,
}

/// Launch QEMU
#[instrument(skip(cancellation_tokens, tool_paths, qemu_launch_opts))]
pub async fn launch_qemu(
    cancellation_tokens: CancellationTokens,
    qemu_should_exit: Arc<AtomicBool>,
    run_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
) -> Result<()> {
    let overlay_image_str = qemu_launch_opts.image_path.to_string_lossy();
    let kernel_path_str = qemu_launch_opts.kernel_initrd.kernel_path.to_string_lossy();
    let initrd_path_str = qemu_launch_opts.kernel_initrd.initrd_path.to_string_lossy();
    let ovmf_uefi_vars_str = qemu_launch_opts.ovmf_uefi_vars_path.to_string_lossy();

    let sysinfo_system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing()
            .with_cpu(sysinfo::CpuRefreshKind::everything())
            .with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let memory = sysinfo_system.total_memory() / 1024 / 1024 / 1024;
    let logical_core_count = sysinfo_system.cpus().len();

    let ssh_pubkey_base64 = Base64::encode_string(qemu_launch_opts.pubkey.as_bytes());

    let cid = qemu_launch_opts.cid;

    let hostfwd: String =
        qemu_launch_opts
            .published_ports
            .iter()
            .fold(String::new(), |mut output, p| {
                let _ = write!(
                    output,
                    ",hostfwd=:{}:{}-:{}",
                    p.host_ip, p.host_port, p.vm_port
                );
                output
            });

    let qmp_socket_path = run_dir.join("qmp.sock,server,wait=off");
    let qmp_socket_path_str = qmp_socket_path.to_string_lossy();

    // In case we're using virtio pmem devices, we'll have to accumulate their memory and add it on
    // top of the regular memory as `maxmem`.
    let total_pmem_size = qemu_launch_opts.pmems.iter().fold(0, |acc, x| acc + x.size);
    let qemu_maxmem = format!(",maxmem={}G", memory + total_pmem_size);

    let mut qemu_cmd = Command::new(tool_paths.qemu_path.clone());
    qemu_cmd
        // Decrease idle CPU usage
        .args(["-machine", "hpet=off"])

        .args(["-accel", "kvm"])
        .args(["-cpu", "host"])
        .args(["-smp", &logical_core_count.to_string()])

        // We extracted the kernel and initrd from this image earlier in order to boot it more
        // quickly.
        .args(["-kernel", &kernel_path_str])
        .args(["-initrd", &initrd_path_str])
        .args(["-append", "rw root=/dev/vda3"])

        // SSH port forwarding
        .args(["-device", &format!("vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={cid}")])

        // Network controller
        .args(["-nic", &format!("user,model=virtio{hostfwd}")])

        // Free Page Reporting allows the guest to signal to the host that memory can be reclaimed.
        .args(["-device", "virtio-balloon,free-page-reporting=on"])

        // Memory configuration
        .args(["-m", &format!("{memory}G{qemu_maxmem}")])
        .args(["-object", &format!("memory-backend-memfd,id=mem0,merge=on,share=on,size={memory}G")])
        .args(["-numa", "node,memdev=mem0"])

        // UEFI
        .args([
            "-drive",
            "if=pflash,format=raw,unit=0,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd,readonly=on",
        ])
        .args([
            "-drive",
            &format!("if=pflash,unit=1,file={ovmf_uefi_vars_str}"),
        ])

        // Overlay image
        .args(["-drive", &format!("if=virtio,node-name=overlay-disk,file={overlay_image_str}")])

        // QMP API to expose QEMU command API
        .args(["-qmp", &format!("unix:{qmp_socket_path_str}")])

        // Here we inject the SSH using systemd.system-credentials, see:
        // https://www.freedesktop.org/software/systemd/man/latest/systemd.system-credentials.html
        .args([
            "-smbios",
            &format!(
                "type=11,value=io.systemd.credential.binary:ssh.authorized_keys.root={ssh_pubkey_base64}"
            ),
        ]);

    // It's important we keep `virtiofsd_handles` in scope here and that we don't drop them too
    // early as otherwise the process would exit and the VM would be unhappy.
    let mut virtiofsd_handles = vec![];

    if !qemu_launch_opts.is_warmup {
        qemu_cmd.arg("-snapshot");

        // We need fstab entries for virtiofsd mounts and pmem devices.
        let mut fstab_entries = vec![];

        // Add virtiofsd-based directory shares
        for (i, vol) in qemu_launch_opts.volumes.iter().enumerate() {
            let virtiofsd_child = launch_virtiofsd(&tool_paths.virtiofsd_path, run_dir, vol)
                .await
                .wrap_err(format!("Failed to launch virtiofsd for {vol}"))?;
            virtiofsd_handles.push(virtiofsd_child);

            let socket_path = run_dir.join(vol.socket_name());
            let socket_path_str = socket_path.to_string_lossy();
            let tag = vol.tag();
            let dest_path = vol.dest.to_string_lossy();
            let read_only = if vol.read_only {
                String::from(",ro")
            } else {
                String::new()
            };
            let fstab_entry = format!("{tag} {dest_path} virtiofs defaults{read_only} 0 0");
            fstab_entries.push(fstab_entry);
            qemu_cmd
                .args([
                    "-chardev",
                    &format!("socket,id=char{i},path={socket_path_str}"),
                ])
                .args([
                    "-device",
                    &format!("vhost-user-fs-pci,chardev=char{i},tag={tag}"),
                ]);
        }

        // Add virtio-pmem devices
        for (i, pmem) in qemu_launch_opts.pmems.iter().enumerate() {
            // Systemd will conveniently auto-format the device on mount, neat!
            let fstab_entry = format!(
                "/dev/pmem{i} {} ext4 rw,relatime,dax=always,x-systemd.makefs 0 0",
                pmem.dest.to_string_lossy()
            );
            fstab_entries.push(fstab_entry);

            let pmem_file = run_dir.join(format!("pmem{i}.pmem"));
            qemu_cmd.args([
                "-object",
                &format!("memory-backend-file,id=pmem{i},share=on,merge=on,discard-data=on,mem-path={},size={}G", pmem_file.to_string_lossy(), pmem.size)]);
            qemu_cmd.args([
                "-device",
                &format!("virtio-pmem-pci,memdev=pmem{i},id=nv{i}"),
            ]);
        }

        if !fstab_entries.is_empty() {
            let fstab = fstab_entries.join("\n");
            let fstab_base64 = Base64::encode_string(fstab.as_bytes());
            qemu_cmd.args([
                "-smbios",
                &format!("type=11,value=io.systemd.credential.binary:fstab.extra={fstab_base64}"),
            ]);
        }
    }

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
            if qemu_should_exit.load(Ordering::SeqCst) {
                info!("QEMU has finished running");
                return Ok(());
            }
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
