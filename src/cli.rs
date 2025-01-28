use std::{path::PathBuf, time::Duration};

use clap::{Args, Parser, ValueEnum};

/// The operating system to run
#[derive(Debug, Clone, ValueEnum)]
pub enum OsType {
    Archlinux,
}

#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = false)]
pub struct ImageSource {
    /// Operating system to run
    #[arg(short, long)]
    pub os: Option<OsType>,

    /// Path to an image
    #[arg(short, long, value_parser = parse_existing_pathbuf)]
    pub image: Option<PathBuf>,
}

/// Parse a string the format `source:dest`
fn parse_bind_mount(src: &str) -> Result<BindMount, String> {
    let parts: Vec<&str> = src.split(':').collect();
    if parts.len() != 2 {
        return Err("Expected format: source:dest".to_string());
    }

    let source = PathBuf::from(parts[0]);
    if !source.is_absolute() {
        return Err("source must be an absolute path".to_string());
    }
    if !source.exists() {
        return Err("source doesn't exist".to_string());
    }

    let dest = PathBuf::from(parts[1]);
    if !dest.is_absolute() {
        return Err("dest must be an absolute path".to_string());
    }

    Ok(BindMount { source, dest })
}

/// Parse a string into a canonicalized PathBuf and validate that it exists
fn parse_existing_pathbuf(src: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(src)
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize path: {}", e))?;
    Ok(path)
}

/// Parse a string into a Duration
fn parse_seconds_to_duration(src: &str) -> Result<Duration, String> {
    let sec_int = src
        .parse()
        .map_err(|_e| format!("Failed to parse '{src}' as an integer"))?;
    Ok(Duration::from_secs(sec_int))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub dest: PathBuf,
}

/// Run a command in a new virtual machine
#[derive(Debug, Clone, Parser)]
#[command(name = "vmexec", author, about, version)]
pub struct Cli {
    #[arg(long)]
    pub verbose: bool,

    #[command(flatten)]
    pub image_source: ImageSource,

    /// Set environment variables for the process inside the virtual machine
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Bind mount a volume into the virtual machine
    #[arg(short, long, value_parser(parse_bind_mount))]
    pub volume: Vec<BindMount>,

    /// Explicit temporary directory
    ///
    /// If not provided, a safe default will be generated.
    #[arg(short, long, value_parser(parse_existing_pathbuf))]
    pub tmpdir: Option<PathBuf>,

    /// SSH connection timeout
    ///
    /// Try for this long (in seconds) to connect to the VMs SSH server.
    #[arg(
        short,
        long,
        default_value = "20",
        value_parser(parse_seconds_to_duration)
    )]
    pub ssh_timeout: Duration,

    /// Show a window with the virtual machine running in it.
    ///
    /// This is mostly useful for debugging boot failures.
    #[arg(long)]
    pub show_vm_window: bool,

    /// Arguments to run in the virtual machine
    pub args: Vec<String>,

    /// Generate completion file for a shell
    #[arg(long = "print-completions", value_name = "shell")]
    pub print_completions: Option<clap_complete::Shell>,

    /// Generate man page
    #[arg(long = "print-manpage")]
    pub print_manpage: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest(
        volume_input,
        source,
        dest,
        case("/tmp:/tmp", "/tmp", "/tmp"),
        case("/usr/bin:/somewhere/else", "/usr/bin", "/somewhere/else")
    )]
    fn test_parse_bind_volume_valid(volume_input: &str, source: PathBuf, dest: PathBuf) {
        let actual = parse_bind_mount(volume_input).unwrap();
        let expected = BindMount { source, dest };
        assert_eq!(actual, expected);
    }

    #[rstest(
        volume_input,
        expected,
        case("tmp:/tmp", "source must be an absolute path"),
        case("/nowhere:/tmp", "source doesn't exist"),
        case("/tmp:tmp", "dest must be an absolute path"),
        case("/tmp", "Expected format: source:dest"),
        case("/tmp:/tmp:something", "Expected format: source:dest")
    )]
    fn test_parse_bind_volume_invalid(volume_input: &str, expected: &str) {
        let actual = parse_bind_mount(volume_input).unwrap_err();
        assert_eq!(actual, expected);
    }
}
