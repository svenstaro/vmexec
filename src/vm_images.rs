use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, Context, OptionExt, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rattler_digest::{compute_file_digest, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::{debug, info, instrument, trace};
use url::Url;

use crate::cli::Pull;

/// Download the most recent Arch Linux image
#[instrument]
pub async fn download_archlinux(pull: Pull, dir: &Path) -> Result<PathBuf> {
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
        .ok_or_eyre("No line break in output")?;
    let build_version = build_version_line
        .split('=')
        .next_back()
        .ok_or_eyre(format!(
            "BUILD_VERSION line not in expected format: {build_version_line}"
        ))?;

    let image_name = format!("Arch-Linux-x86_64-libvirt-executor-{build_version}.qcow2");

    // The file will be downloaded to this path.
    let local_image_path = dir.join(&image_name);

    let image_ext = local_image_path
        .extension()
        .ok_or_eyre("Somehow the image '{local_image_path:?}' didn't have a file extension")?
        .to_str()
        .ok_or_eyre("File extension in '{image_ext}' isn't ASCII")?;
    let local_image_checksum_path = local_image_path.with_extension(format!("{image_ext}.SHA256"));

    // First check if the files even need downloading or whether we already have them.
    if local_image_path.exists() && local_image_checksum_path.exists() {
        debug!("Found pre-existing files for image, skipping download");
        return Ok(local_image_path);
    } else {
        match pull {
            Pull::Never => bail!("Image not found locally and pull option never chosen"),
            Pull::Newer => debug!("Didn't find requested image locally, proceeding to download"),
        }
    }

    let image_url = arch_boxes_base_url.join(&format!("output/{image_name}?job=build:secure"))?;
    let image_checksum_url =
        arch_boxes_base_url.join(&format!("output/{image_name}.SHA256?job=build:secure"))?;

    trace!("Getting Arch Linux image checksum from '{image_checksum_url}'");

    let mut image_checksum = reqwest::get(image_checksum_url)
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    fs::write(&local_image_checksum_path, &image_checksum)
        .await
        .wrap_err(format!(
            "Can't write checksum file to '{local_image_checksum_path:?}'"
        ))?;

    let mut local_image_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&local_image_path)
        .await?;

    trace!("Resolving Arch Linux image at {image_url}");

    let mut image_resp = reqwest::get(image_url.clone()).await?.error_for_status()?;
    let image_size = image_resp
        .content_length()
        .ok_or_eyre("Couldn't get image size")?;

    debug!("Resolved as {} with {} bytes", image_resp.url(), image_size);

    let progress = ProgressBar::new(image_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{bar:40.green/black}] {bytes:>11.green}/{total_bytes:<11.green} {bytes_per_sec:>13.red} eta {eta:.blue}")?
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    progress.set_message(format!("Downloading {}", image_resp.url()));

    while let Some(chunk) = image_resp.chunk().await? {
        local_image_file.write_all(&chunk).await?;
        progress.inc(chunk.len() as u64);
    }
    progress.finish_with_message("Download complete!");

    info!("Checking file checksum");

    // The hash file we downloaded is in the format "hash filename" so we'll have to cut off the
    // first part to get just the hash.
    image_checksum.truncate(64);
    let image_checksum_raw = hex::decode(image_checksum)?;

    let computed_checksum = compute_file_digest::<Sha256>(&local_image_path)?;
    if image_checksum_raw != computed_checksum.as_slice() {
        bail!("Checksum mismatch on {local_image_path:?}, maybe the file got corrupted somehow. Try deleting it and retrying.");
    }

    Ok(local_image_path)
}
