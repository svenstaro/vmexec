use std::path::Path;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rattler_digest::{compute_file_digest, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::{debug, info, instrument, trace};
use url::Url;

/// Download the most recent Arch Linux image
#[instrument]
pub async fn download_archlinux(dir: &Path) -> Result<()> {
    let arch_boxes_base_url = Url::parse(
        "https://gitlab.archlinux.org/archlinux/arch-boxes/-/jobs/artifacts/master/raw/",
    )?;
    let build_version_url = arch_boxes_base_url.join("build.env?job=build:secure")?;

    // Figure out what the current version is.
    let build_version = reqwest::get(build_version_url)
        .await?
        .error_for_status()?
        .text()
        .await?;
    let build_version_line = build_version
        .lines()
        .next()
        .context("No line break in output")?;
    let build_version = build_version_line.split('=').next_back().context(format!(
        "BUILD_VERSION line not in expected format: {build_version_line}"
    ))?;

    let image_name = format!("Arch-Linux-x86_64-libvirt-executor-{build_version}.qcow2");

    // The file will be downloaded to this path.
    let local_image_path = dir.join(&image_name);
    let local_image_checksum_path = local_image_path.join(".SHA256");

    let image_url = arch_boxes_base_url.join(&format!("output/{image_name}?job=build:secure"))?;
    let image_checksum_url =
        arch_boxes_base_url.join(&format!("output/{image_name}.SHA256?job=build:secure"))?;

    trace!("Getting Arch Linux image checksum from {image_checksum_url}");

    let image_checksum = reqwest::get(image_checksum_url)
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    dbg!("omg");
    fs::write(local_image_checksum_path, &image_checksum).await?;
    dbg!("rofl");

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&local_image_path)
        .await?;

    trace!("Resolving Arch Linux image at {image_url}");

    let mut image_resp = reqwest::get(image_url.clone()).await?.error_for_status()?;
    let image_size = image_resp
        .content_length()
        .context("Couldn't get image size")?;

    debug!("Resolved as {} with {} bytes", image_resp.url(), image_size);

    let progress = ProgressBar::new(image_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{bar:40.green/black}] {bytes:>11.green}/{total_bytes:<11.green} {bytes_per_sec:>13.red} eta {eta:.blue}")?
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    progress.set_message(format!("Downloading {}", image_resp.url()));

    while let Some(chunk) = image_resp.chunk().await? {
        file.write_all(&chunk).await?;
        progress.inc(chunk.len() as u64);
    }

    info!("Checking file checksum");

    let computed_checksum = compute_file_digest::<Sha256>(&local_image_path)?;
    if *image_checksum != *computed_checksum {
        bail!("Checksum mismatch on {local_image_path:?}, maybe the file got corrupted somehow. Try deleting it and retrying.");
    }

    progress.finish_with_message("Download complete!");

    Ok(())
}
