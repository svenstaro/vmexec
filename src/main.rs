use std::os::unix::fs::PermissionsExt;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::Result;
use base64ct::Encoding;
use clap::{crate_name, CommandFactory, Parser};
use rustix::{fs::IFlags, io::Errno, path::Arg};
use ssh_key::private::Ed25519Keypair;
use tokio::{
    fs::{self, File},
    process::Command,
};
use tracing::{debug, error};
use utils::full_cmd;

mod cli;
mod utils;

/// Create SSH key to be used with the virtual machine
async fn create_ssh_key(tmpdir: &Path) -> Result<(String, String)> {
    let ssh_privkey_path = tmpdir.join("id_ed25519");
    let ssh_pubkey_path = ssh_privkey_path.with_extension("pub");

    let ed25519_keypair = Ed25519Keypair::random(&mut ssh_key::rand_core::OsRng);

    let pubkey_openssh = ssh_key::PublicKey::from(ed25519_keypair.public).to_openssh()?;
    debug!("Writing SSH public key to {ssh_pubkey_path:?}");
    fs::write(ssh_pubkey_path, &pubkey_openssh).await?;

    let privkey_openssh = ssh_key::PrivateKey::from(ed25519_keypair)
        .to_openssh(ssh_key::LineEnding::default())?
        .to_string();
    debug!("Writing SSH private key to {ssh_privkey_path:?}");

    // TODO Maybe make this nicer
    fs::write(&ssh_privkey_path, &privkey_openssh).await?;
    let mut perms = fs::metadata(&ssh_privkey_path).await?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(ssh_privkey_path, perms).await?;

    Ok((pubkey_openssh, privkey_openssh))
}

/// Create an overlay image based on a source image
async fn create_overlay_image(tmpdir: &Path, source_image: &Path) -> Result<PathBuf> {
    let overlay_image = tmpdir.join("overlay.qcow2");

    // Touch the file so that it exists.
    let overlay_image_fd = File::create(&overlay_image).await?;

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
    debug!("Running: {qemu_img_cmd_str}");

    let qemu_img_output = qemu_img_cmd.output().await?;
    if !qemu_img_output.status.success() {
        error!(
            "qemu-img failed: {}",
            String::from_utf8_lossy(&qemu_img_output.stderr)
        );
    }

    Ok(overlay_image)
}

/// Launch QEMU
async fn launch_qemu(tmpdir: &Path, overlay_image: &Path, ssh_pubkey: String) -> Result<()> {
    let ovmf_vars = tmpdir.join("OVMF_VARS.4m.fd");
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

    let mut qemu_cmd = Command::new("qemu-system-x86_64");
    qemu_cmd
        .arg("-enable-kvm")
        .arg("-nographic")
        .args(["-m", &format!("{memory}G")])
        .args(["-cpu", "host"])
        .args(["-smp", &logical_core_count.to_string()])
        .args(["-nic", "user,model=virtio-net-pci,hostfwd=tcp::2222-:22"])
        .args(["-device", "virtio-balloon,free-page-reporting=on"])
        .args([
            "-drive",
            "if=pflash,format=raw,unit=0,file=/usr/share/edk2/x64/OVMF.4m.fd,readonly=on",
        ])
        .args([
            "-drive",
            &format!("if=pflash,format=raw,unit=1,file={ovmf_vars_str}"),
        ])
        .args(["-drive", &format!("if=virtio,file={overlay_image_str}")])
        .args([
            "-smbios",
            &format!(
                "type=11,value=io.systemd.credential.binary:ssh.authorized_keys.root={ssh_pubkey_base64}"
            ),
        ]);
    // TODO This isn't working somehow
    //.args([
    //    "-smbios",
    //    &format!("type=11,value=io.systemd.credential:passwd.plaintext-password.root=lol"),
    //]);

    let qemu_cmd_str = full_cmd(&qemu_cmd);
    debug!("Running: {qemu_cmd_str}");

    let qemu_child = qemu_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let qemu_output = qemu_child.wait_with_output().await?;
    if !qemu_output.status.success() {
        error!(
            "qemu failed: {}",
            String::from_utf8_lossy(&qemu_output.stderr)
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Cli::parse();
    dbg!(&args);

    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(format!("{}=debug", crate_name!()))
            .init();
    }

    if let Some(shell) = args.print_completions {
        let mut clap_app = cli::Cli::command();
        let app_name = clap_app.get_name().to_string();
        clap_complete::generate(shell, &mut clap_app, app_name, &mut std::io::stdout());
        return Ok(());
    }

    if args.print_manpage {
        let clap_app = cli::Cli::command();
        let man = clap_mangen::Man::new(clap_app);
        man.render(&mut std::io::stdout())?;
        return Ok(());
    }

    let image = if let Some(_os) = args.image_source.os {
        unimplemented!("Handle this");
    } else if let Some(image) = args.image_source.image {
        image
    } else {
        unreachable!();
    };

    let tmpdir = tempfile::tempdir()?;

    if args.tmpdir.is_some() {
        unimplemented!("Meh");
    }

    let (ssh_pubkey, ssh_privkey) = create_ssh_key(&tmpdir.path()).await?;
    let overlay_image = create_overlay_image(&tmpdir.path(), &image).await?;

    launch_qemu(&tmpdir.path(), &overlay_image, ssh_pubkey).await?;

    Ok(())
}
