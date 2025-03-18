use std::path::Path;

use clap::{CommandFactory, Parser, crate_name};
use color_eyre::eyre::{Context, Result, bail};
use dir_lock::DirLock;
use qemu::convert_ovmf_uefi_variables;
use tempfile::TempDir;
use termion::{color, style};
use tokio::fs::{self, read_to_string};
use tokio::process;
use tracing::{Level, debug, instrument, trace};
use utils::VmexecDirs;

mod cli;
mod qemu;
mod runner;
mod ssh;
mod utils;
mod vm_images;

use crate::cli::{Command, KsmCommand, RunCommand};
use crate::qemu::KernelInitrd;
use crate::ssh::ensure_ssh_key;
use crate::utils::{check_ksm_active, create_free_cid, find_required_tools, print_ksm_stats};
use crate::vm_images::ensure_archlinux_image;

fn install_tracing(log_level: Level) {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

    let format = fmt::format::debug_fn(|writer, field, value| {
        if field.name() == "message" {
            write!(writer, "{:?}", value)
        } else {
            // We'll format the field name and value separated with a colon.
            write!(writer, "")
        }
    })
    // Separate each field with a comma.
    // This method is provided by an extension trait in the
    // `tracing-subscriber` prelude.
    .delimited("");

    let filter_layer = EnvFilter::try_new(format!("{}={}", crate_name!(), log_level)).unwrap();

    let subscriber = tracing_subscriber::registry()
        .with(filter_layer)
        .with(ErrorLayer::default());

    if log_level <= Level::INFO {
        let fmt_layer = fmt::layer().with_target(false).compact().fmt_fields(format);
        subscriber.with(fmt_layer).init();
    } else {
        let fmt_layer = fmt::layer().with_target(false).compact();
        subscriber.with(fmt_layer).init();
    };
}

async fn ksm_command(ksm_args: KsmCommand) -> Result<()> {
    if let Some(enable_disable) = ksm_args.ksm_enable_disable {
        if whoami::username() != "root" {
            bail!("You need to run this particular subcommand as root");
        }

        if enable_disable.enable {
            println!("Writing KSM config to /etc/tmpfiles.d/ksm.conf and reloading systemd");
            let ksm_conf = "\
w /sys/kernel/mm/ksm/run - - - - 1
w /sys/kernel/mm/ksm/advisor_mode - - - - scan-time
";
            fs::write("/etc/tmpfiles.d/ksm.conf", ksm_conf).await?;
            process::Command::new("systemd-tmpfiles")
                .arg("--create")
                .output()
                .await?;
        } else if enable_disable.disable {
            println!("Removing KSM config at /etc/tmpfiles.d/ksm.conf and reloading systemd");
            fs::write("/sys/kernel/mm/ksm/run", "0").await?;
            fs::write("/sys/kernel/mm/ksm/advisor_mode", "none").await?;
            fs::remove_file("/etc/tmpfiles.d/ksm.conf").await?;
        }
    } else {
        let ksm_enabled = read_to_string("/sys/kernel/mm/ksm/run").await?.trim() == "1";
        if ksm_enabled {
            println!(
                "{}KSM status: {}enabled{}",
                style::Bold,
                color::Fg(color::LightGreen),
                style::Reset,
            );
            print_ksm_stats().await?;
        } else {
            println!(
                "{}KSM status: {}disabled{}",
                style::Bold,
                color::Fg(color::Yellow),
                style::Reset
            );
        }
    }
    Ok(())
}

async fn run_command(run_args: RunCommand) -> Result<()> {
    // Make sure the tools we need are actually installed.
    let tool_paths = find_required_tools().await?;

    // Check whether KSM is active.
    check_ksm_active().await?;

    let dirs = VmexecDirs::new().await?;

    // TODO reap dead run dirs here

    // Dir for this run (usually ~/.local/share/vmexec/runs/<random id>/)
    // Temporary and self-deleting so we don't end up with a lot of garbage after some time.
    let run_dir = TempDir::with_prefix_in("run", &dirs.runs_dir)
        .wrap_err(format!("Couldn't make temp dir in {:?}", dirs.runs_dir))?;
    debug!("run dir is: {:?}", run_dir.path());

    let image_path = if let Some(os) = run_args.image_source.os {
        let lock_dir = dirs.cache_dir.join("lockdir");
        trace!("Trying to lock {lock_dir:?}");
        let _ = DirLock::new(lock_dir).await?;
        match os {
            cli::OsType::Archlinux => {
                ensure_archlinux_image(&dirs.cache_dir, run_args.pull).await?
            }
        }
    } else if let Some(image_path) = run_args.image_source.image {
        image_path
    } else {
        unreachable!();
    };

    let ssh_keypair = ensure_ssh_key(&dirs.secrets_dir).await?;

    // We need a free CID for host-guest communication via vsock.
    let cid = create_free_cid(&dirs.runs_dir, run_dir.path()).await?;

    let kernel_initrd = if let Some(image_dir) = image_path.parent() {
        KernelInitrd {
            kernel_path: image_dir.join("vmlinuz-linux"),
            initrd_path: image_dir.join("initramfs-linux.img"),
        }
    } else {
        bail!("Somehow {image_path:?} didn't have a parent");
    };

    let ovmf_vars_system_path = Path::new("/usr/share/edk2/x64/OVMF_VARS.4m.fd");
    let ovmf_vars = convert_ovmf_uefi_variables(run_dir.path(), ovmf_vars_system_path).await?;

    let qemu_launch_opts = qemu::QemuLaunchOpts {
        volumes: run_args.volumes,
        pmems: run_args.pmems,
        published_ports: run_args.published_ports,
        image_path,
        ovmf_uefi_vars_path: ovmf_vars,
        kernel_initrd,
        show_vm_window: run_args.show_vm_window,
        pubkey: ssh_keypair.pubkey_str,
        cid,
        is_warmup: true,
    };

    let ssh_launch_opts = ssh::SshLaunchOpts {
        timeout: run_args.ssh_timeout,
        env_vars: run_args.env,
        args: run_args.args,
        privkey: ssh_keypair.privkey_str,
        cid,
    };

    let overlay_image_path = runner::run_warmup(
        run_dir.path(),
        tool_paths.clone(),
        qemu_launch_opts.clone(),
        ssh_launch_opts.clone(),
    )
    .await?;

    // We create a new `QemuLaunchOpts` here so that we can launch QEMU from the overlay image
    // instead of the source image.
    let qemu_launch_opts = qemu::QemuLaunchOpts {
        image_path: overlay_image_path,
        is_warmup: false,
        ..qemu_launch_opts
    };

    debug!("SSH command for manual debugging:");
    debug!(
        "ssh root@vsock/{cid} -i {privkey_path:?}",
        privkey_path = ssh_keypair.privkey_path
    );
    runner::run_command(
        run_dir.path(),
        tool_paths,
        qemu_launch_opts,
        ssh_launch_opts,
    )
    .await?;

    Ok(())
}

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    install_tracing(cli.log_level);
    color_eyre::install()?;

    match cli.command {
        Command::Ksm(ksm_args) => ksm_command(ksm_args).await?,
        Command::Run(run_args) => run_command(run_args).await?,
        Command::Completions { shell } => {
            let mut clap_app = cli::Cli::command();
            let app_name = clap_app.get_name().to_string();
            clap_complete::generate(shell, &mut clap_app, app_name, &mut std::io::stdout());
        }
        Command::Manpage { out_dir } => {
            let clap_app = cli::Cli::command();
            clap_mangen::generate_to(clap_app, out_dir)?;
        }
    }
    Ok(())
}
