use std::path::{Path, PathBuf};

use async_walkdir::{Filtering, WalkDir};
use color_eyre::eyre::{Context, OptionExt, Result, bail};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use rattler_digest::{Sha256, compute_file_digest};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::{debug, info, instrument, trace};
use url::Url;

use crate::{cli::Pull, utils::ensure_directory};

/// Download Arch Linux image
pub async fn download_archlinux_image(
    local_image_path: &Path,
    local_image_checksum_path: &Path,
    arch_boxes_base_url: &Url,
    image_name: &str,
) -> Result<()> {
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
            "Can't write checksum file to {local_image_checksum_path:?}"
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
        bail!(
            "Checksum mismatch on {local_image_path:?}, maybe the file got corrupted somehow. Try deleting it and retrying."
        );
    }

    Ok(())
}

/// Retrieve the latest locally available Arch Linux image
pub async fn get_latest_local_archlinux_image(distro_image_dir: &Path) -> Result<Option<PathBuf>> {
    let mut images = vec![];

    // First we'll gather a list of all local images.
    let mut entries = WalkDir::new(distro_image_dir).filter(|entry| async move {
        let filename = entry.file_name();
        if entry.file_type().await.unwrap().is_file()
            && filename.to_string_lossy().starts_with("Arch-Linux")
            && entry.path().extension().unwrap_or_default() == "qcow2"
        {
            return Filtering::Continue;
        }
        Filtering::Ignore
    });

    loop {
        match entries.next().await {
            Some(Ok(entry)) => images.push(entry.path().to_owned()),
            Some(Err(e)) => bail!(e),
            None => break,
        }
    }

    // Sort the images by name as the Arch Linux images contain the ISO date so that the latest one
    // will be the one at the very end.
    images.sort();

    let latest_image = images.last().cloned();
    Ok(latest_image)
}

/// Download the most recent Arch Linux image
#[instrument]
pub async fn ensure_archlinux_image(cache_dir: &Path, pull: Pull) -> Result<PathBuf> {
    let distro_image_dir = cache_dir.join("images").join("archlinux");
    ensure_directory("distro image", &distro_image_dir).await?;

    let latest_local_image = get_latest_local_archlinux_image(&distro_image_dir).await?;

    match pull {
        // If --pull missing was provided and if there is already a local image (no matter the age),
        // we'll just return that. If there's no image we'll do nothing which will cause it to be
        // downloaded later in the function.
        Pull::Missing => {
            if let Some(latest) = latest_local_image {
                info!(
                    "Found local image {latest:?} and \"--pull missing\" was provided so this is the image we're using"
                );
                return Ok(latest);
            }
        }
        // If --pull missing was provided and if there is already a local image (no matter the age),
        // we'll just return that. If there's no image we'll error out.
        Pull::Never => {
            if let Some(latest) = latest_local_image {
                info!(
                    "Found local image {latest:?} and \"--pull never\" was provided so this is the image we're using"
                );
                return Ok(latest);
            } else {
                bail!("No local image found and `--pull never` selected, bailing");
            }
        }
        Pull::Newer => {
            if let Some(latest) = latest_local_image {
                info!(
                    "Found local image {latest:?} but there might be a newer image so we're checking"
                );
            }
        }
    }

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

    debug!("Latest remote image is: {image_name}");

    // The file will be downloaded to this path.
    let image_dir = distro_image_dir.join(build_version);
    ensure_directory("image dir", &image_dir).await?;

    let local_image_path = image_dir.join(&image_name);
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
    } else if pull == Pull::Newer {
        debug!("Didn't find requested image locally, proceeding to download");
    }

    // Since we got to this point we'll need to download the image here.
    download_archlinux_image(
        &local_image_path,
        &local_image_checksum_path,
        &arch_boxes_base_url,
        &image_name,
    )
    .await?;

    Ok(local_image_path)
}
