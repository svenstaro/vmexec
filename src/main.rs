use clap::{CommandFactory, Parser, crate_name};
use color_eyre::eyre::{Context, OptionExt, Result, bail};
use directories::ProjectDirs;
use tempfile::TempDir;
use tracing::{Level, debug, instrument};

mod cli;
mod qemu;
mod runner;
mod ssh;
mod utils;
mod vm_images;

use crate::qemu::KernelInitrd;
use crate::ssh::ensure_ssh_key;
use crate::utils::{create_free_cid, ensure_directory, find_required_tools};
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

    // Dir containing cached stuff (usually ~/.config/vmexec/)
    let cache_dir = project_dir.cache_dir();
    ensure_directory("cache", cache_dir).await?;

    // Dir containing persistent data (usually ~/.local/share/vmexec/)
    let data_dir = project_dir.data_dir();
    ensure_directory("data", data_dir).await?;

    // Dir containing secrets (usually ~/.local/share/vmexec/secrets/)
    let secrets_dir = data_dir.join("secrets");
    ensure_directory("secrets", &secrets_dir).await?;

    // Dir containing all runs (usually ~/.local/share/vmexec/runs/)
    let runs_dir = data_dir.join("runs");
    ensure_directory("runs", &runs_dir).await?;

    // Dir for this run (usually ~/.local/share/vmexec/runs/<random id>/)
    // Temporary and self-deleting so we don't end up with a lot of garbage after some time.
    let run_dir = TempDir::with_prefix_in("run", &runs_dir)
        .wrap_err(format!("Couldn't make temp dir in {runs_dir:?}"))?;
    debug!("run dir is: {:?}", runs_dir);

    let image_path = if let Some(os) = cli.image_source.os {
        match os {
            cli::OsType::Archlinux => ensure_archlinux_image(cache_dir, cli.pull).await?,
        }
    } else if let Some(image_path) = cli.image_source.image {
        image_path
    } else {
        unreachable!();
    };

    let ssh_keypair = ensure_ssh_key(&secrets_dir).await?;

    // We need a free CID for host-guest communication via vsock.
    let cid = create_free_cid(&runs_dir, run_dir.path()).await?;

    let kernel_initrd = if let Some(image_dir) = image_path.parent() {
        KernelInitrd {
            kernel_path: image_dir.join("vmlinuz-linux"),
            initrd_path: image_dir.join("initramfs-linux.img"),
        }
    } else {
        bail!("Somehow {image_path:?} didn't have a parent");
    };

    let qemu_launch_opts = qemu::QemuLaunchOpts {
        volumes: cli.volumes,
        image_path,
        kernel_initrd,
        show_vm_window: cli.show_vm_window,
        pubkey: ssh_keypair.pubkey_str,
        cid,
        is_warmup: true,
    };

    let ssh_launch_opts = ssh::SshLaunchOpts {
        timeout: cli.ssh_timeout,
        env_vars: cli.env,
        args: cli.args,
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
