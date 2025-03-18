use std::{fmt::Display, net::Ipv4Addr, path::PathBuf, str::FromStr, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::Level;

use crate::utils::escape_path;

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

#[derive(Debug, Clone, PartialEq)]
pub struct PublishPort {
    pub host_ip: Ipv4Addr,
    pub host_port: u32,
    pub vm_port: u32,
}

impl FromStr for PublishPort {
    type Err = String;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = src.split(':').collect();

        if parts[0].is_empty() {
            return Err("Expected format: [[hostip:][hostport]:]vmport".to_string());
        }

        let (host_ip, host_port, vm_port) = match parts.len() {
            // If there's only a single part, it has to be the `vm_port`.
            1 => {
                let host_ip = Ipv4Addr::UNSPECIFIED;
                let host_port = parts[0]
                    .parse()
                    .map_err(|_| format!("'{}' is not a valid port", parts[0]))?;
                let vm_port = parts[0]
                    .parse()
                    .map_err(|_| format!("'{}' is not a valid port", parts[0]))?;

                (host_ip, host_port, vm_port)
            }
            2 => {
                let host_ip = Ipv4Addr::UNSPECIFIED;
                let host_port = parts[0]
                    .parse()
                    .map_err(|_| format!("'{}' is not a valid port", parts[0]))?;
                let vm_port = parts[1]
                    .parse()
                    .map_err(|_| format!("'{}' is not a valid port", parts[1]))?;
                (host_ip, host_port, vm_port)
            }
            3 => {
                let host_ip = parts[0]
                    .parse()
                    .map_err(|_| format!("'{}' is not a valid IPv4", parts[0]))?;
                let vm_port = parts[2]
                    .parse()
                    .map_err(|_| format!("'{}' is not a valid port", parts[2]))?;
                let host_port = if !parts[1].is_empty() {
                    parts[1]
                        .parse()
                        .map_err(|_| format!("'{}' is not a valid port", parts[1]))?
                } else {
                    vm_port
                };
                (host_ip, host_port, vm_port)
            }
            _ => return Err("Expected format: [[hostip:][hostport]:]vmport".to_string()),
        };

        Ok(Self {
            host_ip,
            host_port,
            vm_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub dest: PathBuf,
    pub read_only: bool,
}

impl BindMount {
    /// Safely printable/escaped path
    pub fn tag(&self) -> String {
        escape_path(&self.dest.to_string_lossy())
    }

    pub fn socket_name(&self) -> String {
        format!("{}.sock", self.tag())
    }
}

impl Display for BindMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let source = self.source.to_string_lossy();
        let dest = self.dest.to_string_lossy();
        if self.read_only {
            write!(f, "{source}:{dest}:ro")
        } else {
            write!(f, "{source}:{dest}")
        }
    }
}

/// Parse a string the format `source:dest`
impl FromStr for BindMount {
    type Err = String;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = src.split(':').collect();
        if parts.len() != 2 && parts.len() != 3 {
            return Err("Expected format: source:dest[:ro]".to_string());
        }

        let source = PathBuf::from(parts[0]);
        if !source.is_absolute() {
            return Err("source must be an absolute path".to_string());
        }
        if !source.is_dir() {
            return Err("source doesn't exist or isn't a directory".to_string());
        }

        let dest = PathBuf::from(parts[1]);
        if !dest.is_absolute() {
            return Err("dest must be an absolute path".to_string());
        }

        // Last part (ro) is optional so we have to check for that.
        if parts.len() == 3 {
            let options = parts[2];
            if options == "ro" {
                return Ok(BindMount {
                    source,
                    dest,
                    read_only: true,
                });
            } else {
                return Err("Expected format: source:dest[:ro]".to_string());
            }
        }

        Ok(BindMount {
            source,
            dest,
            read_only: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmemMount {
    pub dest: PathBuf,
    pub size: u64,
}

impl FromStr for PmemMount {
    type Err = String;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = src.split(':').collect();
        if parts.len() != 2 {
            return Err("Expected format: dest:<size>".to_string());
        }

        let dest = PathBuf::from(parts[0]);
        if !dest.is_absolute() {
            return Err("dest must be an absolute path".to_string());
        }

        let size = if let Ok(size) = parts[1].parse() {
            size
        } else {
            return Err("Couldn't parse size as integer".to_string());
        };

        Ok(PmemMount { dest, size })
    }
}

#[derive(Clone, Debug, PartialEq, ValueEnum)]
pub enum Pull {
    Missing,
    Never,
    Newer,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

impl FromStr for EnvVar {
    type Err = String;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = src.split('=').collect();

        if parts.len() != 2 {
            return Err("Expected format: KEY=VALUE".to_string());
        }
        Ok(Self {
            key: parts[0].to_string(),
            value: parts[1].to_string(),
        })
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Run a command in a new virtual machine
    Run(RunCommand),

    /// Check and change KSM status
    ///
    /// Without flags, this prints the current KSM state and some stats.
    Ksm(KsmCommand),

    /// Generate completion file for a shell
    Completions { shell: clap_complete::Shell },

    /// Print man page
    Manpage { out_dir: PathBuf },
}

#[derive(Debug, Clone, Args)]
pub struct RunCommand {
    #[command(flatten)]
    pub image_source: ImageSource,

    /// Set environment variables for the process inside the virtual machine
    ///
    /// Can be provided multiple times.
    ///
    /// Expected format: KEY=VALUE
    #[arg(short, long, value_parser(EnvVar::from_str))]
    pub env: Vec<EnvVar>,

    /// Bind mount a volume into the virtual machine
    ///
    /// Can be provided multiple times.
    ///
    /// Expected format: source:dest[:ro]
    ///
    /// `ro` can optionally be provided to mark the mount as read-only.
    ///
    /// Example: $PWD/src:/mnt:ro
    #[arg(short, long = "volume", value_parser(BindMount::from_str))]
    pub volumes: Vec<BindMount>,

    /// Mount a virtio-pmem device file into the virtual machine
    ///
    /// You might want to do this to bypass the guest page cache. This is important if you're
    /// overprovisioning your host (i.e. giving VMs more combined memory than the host actually
    /// has) and have a write-heavy workload.
    /// For more info, see: https://www.qemu.org/docs/master/system/devices/virtio-pmem.html
    ///
    /// Can be provided multiple times.
    ///
    /// Size is in gigabytes.
    ///
    /// Expected format: dest:<size>
    ///
    /// Example: /var/lib:20
    #[arg(long = "pmem", value_parser(PmemMount::from_str))]
    pub pmems: Vec<PmemMount>,

    /// Publish a port on the virtual machine to the host
    ///
    /// Can be provided multiple times.
    ///
    /// Expected format: [[hostip:][hostport]:]vmport
    ///
    /// `hostip` is optional and if not provided, the port will be bound on all host IPs.
    ///
    /// `hostport` is optional and if not provided, the same value of `vmport` will be used for the
    /// host port.
    ///
    /// Currently only IPv4 is supported for `hostip`.
    #[arg(short, long = "publish", value_parser(PublishPort::from_str))]
    pub published_ports: Vec<PublishPort>,

    /// SSH connection timeout
    ///
    /// Try for this long (in seconds) to connect to the virtual machine's SSH server.
    #[arg(
        short,
        long,
        default_value = "20",
        value_parser(parse_seconds_to_duration)
    )]
    pub ssh_timeout: Duration,

    /// Show a window with the virtual machine running in it
    ///
    /// This is mostly useful for debugging boot failures.
    #[arg(long)]
    pub show_vm_window: bool,

    /// When to pull a new image
    #[arg(long, default_value = "missing")]
    pub pull: Pull,

    /// Arguments to run in the virtual machine
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct KsmEnableDisable {
    /// Persistently enable KSM by writing settings to /etc/tmpfiles.d/ksm.conf
    #[arg(short, long)]
    pub enable: bool,

    /// Persistently disable KSM by deleting /etc/tmpfiles.d/ksm.conf
    #[arg(short, long)]
    pub disable: bool,
}

#[derive(Debug, Clone, Args)]
pub struct KsmCommand {
    #[command(flatten)]
    pub ksm_enable_disable: Option<KsmEnableDisable>,
}

/// Run a command in a new virtual machine
#[derive(Debug, Clone, Parser)]
#[command(name = "vmexec", author, about, version)]
pub struct Cli {
    /// Log messages above specified level (error, warn, info, debug, trace)
    #[arg(long, default_value = "warn")]
    pub log_level: Level,

    // Subcommand to run
    #[clap(subcommand)]
    pub command: Command,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest]
    #[case("127.0.0.1:8080:80", "127.0.0.1", "8080", "80")]
    #[case("80", "0.0.0.0", "80", "80")]
    #[case("8080:80", "0.0.0.0", "8080", "80")]
    #[case("127.0.0.1::80", "127.0.0.1", "80", "80")]
    fn test_parse_publish_port_valid(
        #[case] input: &str,
        #[case] host_ip: Ipv4Addr,
        #[case] host_port: u32,
        #[case] vm_port: u32,
    ) {
        let actual = PublishPort::from_str(input).unwrap();
        let expected = PublishPort {
            host_ip,
            host_port,
            vm_port,
        };
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("foo", "'foo' is not a valid port")]
    #[case("foo::", "'foo' is not a valid IPv4")]
    #[case("::", "Expected format: [[hostip:][hostport]:]vmport")]
    #[case("1:2:3:4", "Expected format: [[hostip:][hostport]:]vmport")]
    #[case(":80:", "Expected format: [[hostip:][hostport]:]vmport")]
    fn test_parse_publish_port_invalid(#[case] input: &str, #[case] expected: &str) {
        let actual = PublishPort::from_str(input).unwrap_err();
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("/tmp:/tmp", "/tmp", "/tmp", false)]
    #[case("/usr/bin:/somewhere/else", "/usr/bin", "/somewhere/else", false)]
    #[case("/usr/bin:/somewhere/else:ro", "/usr/bin", "/somewhere/else", true)]
    fn test_parse_bind_volume_valid(
        #[case] input: &str,
        #[case] source: PathBuf,
        #[case] dest: PathBuf,
        #[case] read_only: bool,
    ) {
        let actual = BindMount::from_str(input).unwrap();
        let expected = BindMount {
            source,
            dest,
            read_only,
        };
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("tmp:/tmp", "source must be an absolute path")]
    #[case("/nowhere:/tmp", "source doesn't exist or isn't a directory")]
    #[case("/tmp:tmp", "dest must be an absolute path")]
    #[case("/tmp", "Expected format: source:dest[:ro]")]
    #[case("/tmp:/tmp:something", "Expected format: source:dest[:ro]")]
    fn test_parse_bind_volume_invalid(#[case] input: &str, #[case] expected: &str) {
        let actual = BindMount::from_str(input).unwrap_err();
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("/tmp:2", "/tmp", 2)]
    #[case("/tmp:200", "/tmp", 200)]
    fn test_parse_pmem_valid(#[case] input: &str, #[case] dest: PathBuf, #[case] size: u64) {
        let actual = PmemMount::from_str(input).unwrap();
        let expected = PmemMount { dest, size };
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("tmp:2", "dest must be an absolute path")]
    fn test_parse_pmem_invalid(#[case] input: &str, #[case] expected: &str) {
        let actual = PmemMount::from_str(input).unwrap_err();
        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("key=value", "key", "value")]
    #[case("KEY=VALUE", "KEY", "VALUE")]
    fn test_parse_env_var_valid(#[case] input: &str, #[case] key: String, #[case] value: String) {
        let actual = EnvVar::from_str(input).unwrap();
        let expected = EnvVar { key, value };

        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case("keyvalue", "Expected format: KEY=VALUE")]
    #[case("=key=value", "Expected format: KEY=VALUE")]
    #[case("key=value=", "Expected format: KEY=VALUE")]
    fn test_parse_env_var_invalid(#[case] input: &str, #[case] expected: &str) {
        let actual = EnvVar::from_str(input).unwrap_err();
        assert_eq!(actual, expected);
    }
}
