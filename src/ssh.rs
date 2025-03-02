use std::fmt::Debug;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{env, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use base64ct::LineEnding;
use color_eyre::eyre::{Result, bail};
use russh::keys::ssh_key::{private::Ed25519Keypair, rand_core::OsRng};
use russh::keys::{PrivateKey, PublicKey};
use russh::{ChannelMsg, Disconnect, keys::key::PrivateKeyWithHashAlg};
use termion::raw::IntoRawMode;
use tokio::time::Instant;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, error, info, instrument};

use crate::cli::EnvVar;
use crate::runner::CancellationTokens;

#[derive(Clone, Debug)]
pub struct PersistedSshKeypair {
    pub pubkey_str: String,
    pub _pubkey_path: PathBuf,
    pub privkey_str: String,
    pub privkey_path: PathBuf,
}

impl PersistedSshKeypair {
    // Try to load a keypair from `dir`
    pub async fn from_dir(dir: &Path) -> Result<Self> {
        let privkey_path = dir.join("id_ed25519");
        let pubkey_path = privkey_path.with_extension("pub");
        let privkey_str = fs::read_to_string(&privkey_path).await?;
        let pubkey_str = fs::read_to_string(&pubkey_path).await?;

        Ok(Self {
            pubkey_str,
            _pubkey_path: pubkey_path,
            privkey_str,
            privkey_path,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SshLaunchOpts {
    pub privkey: String,
    pub timeout: Duration,
    pub env_vars: Vec<EnvVar>,
    pub args: Vec<String>,
    pub cid: u32,
}

/// Retrieve or create SSH keypair from `path` to be used with the virtual machine
#[instrument]
pub async fn ensure_ssh_key(dir: &Path) -> Result<PersistedSshKeypair> {
    // First try reading an existing keypair from disk.
    // If that fails we'll just create a new one.
    if let Ok(existing_keypair) = PersistedSshKeypair::from_dir(dir).await {
        return Ok(existing_keypair);
    }

    let privkey_path = dir.join("id_ed25519");
    let pubkey_path = privkey_path.with_extension("pub");

    let ed25519_keypair = Ed25519Keypair::random(&mut OsRng);

    let pubkey_openssh = PublicKey::from(ed25519_keypair.public).to_openssh()?;
    debug!("Writing SSH public key to {pubkey_path:?}");
    fs::write(&pubkey_path, &pubkey_openssh).await?;

    let privkey_openssh = PrivateKey::from(ed25519_keypair)
        .to_openssh(LineEnding::default())?
        .to_string();
    debug!("Writing SSH private key to {privkey_path:?}");

    fs::write(&privkey_path, &privkey_openssh).await?;
    let mut perms = fs::metadata(&privkey_path).await?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&privkey_path, perms).await?;

    let keypair = PersistedSshKeypair {
        pubkey_str: pubkey_openssh,
        _pubkey_path: pubkey_path,
        privkey_str: privkey_openssh,
        privkey_path,
    };
    Ok(keypair)
}

#[derive(Debug, Clone)]
struct SshClient {}

// More SSH event handlers can be defined in this trait
//
// In this example, we're only using Channel, so these aren't needed.
impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    #[instrument]
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// This struct is a convenience wrapper around a russh client that handles the input/output event
/// loop
pub struct Session {
    session: russh::client::Handle<SshClient>,
    terminal_size: (u16, u16),
}

impl Session {
    #[instrument(skip(privkey))]
    async fn connect(privkey: PrivateKey, cid: u32, port: u32, timeout: Duration) -> Result<Self> {
        let config = russh::client::Config {
            keepalive_interval: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = SshClient {};

        let vsock_addr = VsockAddr::new(cid, port);
        let now = Instant::now();
        debug!("Connecting to SSH via vsock");
        let mut session = loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            // I would like to apologize for the error handling below.

            // Establish vsock connection
            let stream = match VsockStream::connect(vsock_addr).await {
                Ok(stream) => stream,
                Err(ref e) if e.raw_os_error() == Some(19) => {
                    // This is "No such device" but for some reason Rust doesn't have an IO
                    // ErrorKind for it. Meh.
                    if now.elapsed() > timeout {
                        error!(
                            "Reached timeout trying to connect to virtual machine via SSH, aborting"
                        );
                        bail!("Timeout");
                    }
                    continue;
                }
                Err(ref e) => match e.kind() {
                    ErrorKind::TimedOut
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset => {
                        if now.elapsed() > timeout {
                            error!(
                                "Reached timeout trying to connect to virtual machine via SSH, aborting"
                            );
                            bail!("Timeout");
                        }
                        continue;
                    }
                    e => {
                        error!("Unhandled error occured: {e}");
                        bail!("Unknown error");
                    }
                },
            };

            // Connect to SSH via vsock stream
            match russh::client::connect_stream(config.clone(), stream, sh.clone()).await {
                Ok(x) => break x,
                Err(russh::Error::IO(ref e)) => {
                    match e.kind() {
                        // The VM is still booting at this point so we're just ignoring these errors
                        // for some time.
                        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
                            if now.elapsed() > timeout {
                                error!(
                                    "Reached timeout trying to connect to virtual machine via SSH, aborting"
                                );
                                bail!("Timeout");
                            }
                        }
                        e => {
                            error!("Unhandled error occured: {e}");
                            bail!("Unknown error");
                        }
                    }
                }
                Err(russh::Error::Disconnect) => {
                    if now.elapsed() > timeout {
                        error!(
                            "Reached timeout trying to connect to virtual machine via SSH, aborting"
                        );
                        bail!("Timeout");
                    }
                }
                Err(e) => {
                    error!("Unhandled error occured: {e}");
                    bail!("Unknown error");
                }
            }
        };
        debug!("Authenticating via SSH");

        // use publickey authentication
        let auth_res = session
            .authenticate_publickey("root", PrivateKeyWithHashAlg::new(Arc::new(privkey), None))
            .await?;

        if !auth_res.success() {
            bail!("Authentication (with publickey) failed");
        }

        Ok(Self {
            session,
            terminal_size: termion::terminal_size()?,
        })
    }

    #[instrument(skip(self))]
    async fn call(&mut self, env: Vec<EnvVar>, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // Request an interactive PTY from the server
        channel
            .request_pty(
                true,
                &env::var("TERM").unwrap_or("xterm-256color".into()),
                self.terminal_size.0 as u32,
                self.terminal_size.1 as u32,
                0,
                0,
                &[], // ideally you want to pass the actual terminal modes here
            )
            .await?;

        for e in env {
            channel.set_env(true, e.key, e.value).await?;
        }

        //channel.request_shell(true).await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdin = tokio_fd::AsyncFd::try_from(libc::STDIN_FILENO)?;
        let mut stdout = tokio_fd::AsyncFd::try_from(libc::STDOUT_FILENO)?;
        let mut buf = vec![0; 1024];
        let mut stdin_closed = false;

        loop {
            // Handle one of the possible events:
            tokio::select! {
                // Handle terminal resize
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    let new_terminal_size = termion::terminal_size()?;
                    if self.terminal_size != new_terminal_size {
                        debug!("Terminal size change detected");
                        self.terminal_size = new_terminal_size;
                        channel.window_change(new_terminal_size.0 as u32, new_terminal_size.1 as u32, 0, 0).await?;
                    }
                },
                // There's terminal input available from the user
                r = stdin.read(&mut buf), if !stdin_closed => {
                    match r {
                        Ok(0) => {
                            stdin_closed = true;
                            channel.eof().await?;
                        },
                        // Send it to the server
                        Ok(n) => channel.data(&buf[..n]).await?,
                        Err(e) => return Err(e.into()),
                    };
                },
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {
                        // Write data to the terminal
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        // The command has returned an exit code
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            if !stdin_closed {
                                channel.eof().await?;
                            }
                            break;
                        }
                        _ => {}
                    }
                },
            }
        }
        Ok(code)
    }

    #[instrument(skip(self))]
    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

/// Connect SSH and run an interactive session
#[instrument(skip(cancellation_tokens, ssh_launch_opts))]
pub async fn connect_ssh_interactive(
    cancellation_tokens: CancellationTokens,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<()> {
    let privkey = PrivateKey::from_openssh(ssh_launch_opts.privkey)?;

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(privkey, ssh_launch_opts.cid, 22, ssh_launch_opts.timeout)
        .await
        .inspect_err(|_| {
            cancellation_tokens.qemu.cancel();
        })?;
    info!("Connected");

    let code = {
        // We're using `termion` to put the terminal into raw mode, so that we can
        // display the output of interactive applications correctly
        let _raw_term = std::io::stdout().into_raw_mode()?;

        let escaped_args = &ssh_launch_opts
            .args
            .into_iter()
            .map(|x| shell_escape::escape(x.into())) // arguments are escaped manually since the SSH protocol doesn't support quoting
            .collect::<Vec<_>>()
            .join(" ");
        let ssh_output = tokio::select! {
            _ = cancellation_tokens.ssh.cancelled() => {
                debug!("SSH task was cancelled");
                return Ok(())
            }
            val = ssh.call(ssh_launch_opts.env_vars, escaped_args) => {
                val
            }
        };
        cancellation_tokens.qemu.cancel();
        ssh_output?
    };

    info!("Exit code: {:?}", code);
    cancellation_tokens.qemu.cancel();
    ssh.close().await?;
    Ok(())
}

/// Connect SSH and run a command that checks whether the system is ready for operation and then
/// shuts down.
///
/// The `qemu_should_exit` is used to tell the QEMU process to wait for process completion once
/// we've told the VM to shutdown. We then wait on the receiver `qemu_has_exited_rx` to know when
/// QEMU has actually exited according to the handler.
#[instrument(skip(ssh_launch_opts))]
pub async fn connect_ssh_for_warmup(
    qemu_should_exit: Arc<AtomicBool>,
    ssh_launch_opts: SshLaunchOpts,
) -> Result<()> {
    let privkey = PrivateKey::from_openssh(ssh_launch_opts.privkey)?;

    // Session is a wrapper around a russh client, defined down below
    let mut ssh =
        Session::connect(privkey, ssh_launch_opts.cid, 22, ssh_launch_opts.timeout).await?;
    info!("Connected");

    // First we'll wait until the system has fully booted up
    let is_running_exitcode = ssh
        .call(vec![], "systemctl is-system-running --wait")
        .await?;
    debug!("systemctl is-system-running --wait exit code {is_running_exitcode}");

    // TODO: Here we'll add a stupid hack to deal with
    // https://github.com/linux-pam/linux-pam/issues/885 for the time being.
    ssh.call(vec![], "echo 127.0.0.1 unknown >> /etc/hosts")
        .await?;
    ssh.call(vec![], "cat /etc/hosts").await?;

    // Then shut the system down
    ssh.call(vec![], "systemctl poweroff").await?;
    debug!("Shutting down system");

    // Tell the QEMU handler it's now fine to wait for exit.
    qemu_should_exit.store(true, Ordering::SeqCst);

    // Ignore whatever error we might get from this as we want to close the connection at this
    // point anyway.
    let _ = ssh.close().await;
    Ok(())
}
