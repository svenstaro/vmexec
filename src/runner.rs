use std::path::Path;

use color_eyre::eyre::Result;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    qemu::{launch_qemu, QemuLaunchOpts},
    ssh::{connect_ssh, SshLaunchOpts},
    utils::ExecutablePaths,
};

#[derive(Debug, Clone, Default)]
pub struct CancellationTokens {
    pub qemu: CancellationToken,
    pub ssh: CancellationToken,
}

#[instrument]
pub async fn run_warmup() {}

#[instrument]
pub async fn run_command(
    run_data_dir: &Path,
    tool_paths: ExecutablePaths,
    qemu_launch_opts: QemuLaunchOpts,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<()> {
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
        async move { connect_ssh(cancellatation_tokens_, ssh_launch_opts).await }
    });

    while let Some(res) = joinset.join_next().await {
        res??
    }

    Ok(())
}
