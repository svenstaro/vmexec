use std::fmt::Debug;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::{env, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use base64ct::LineEnding;
use color_eyre::eyre::{bail, Result};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{PrivateKey, PublicKey};
use russh::{keys::key::PrivateKeyWithHashAlg, ChannelMsg, Disconnect};
use termion::raw::IntoRawMode;
use tokio::time::Instant;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::ToSocketAddrs,
};
use tokio_util::sync::CancellationToken;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, error, info, instrument};

use crate::cli::EnvVar;

#[derive(Clone, Debug)]
pub struct PersistedSshKeypair {
    pub pubkey_str: String,
    pub _pubkey_path: PathBuf,
    pub privkey_str: String,
    pub privkey_path: PathBuf,
}

/// Create SSH key to be used with the virtual machine
#[instrument]
pub async fn create_ssh_key(dir: &Path) -> Result<PersistedSshKeypair> {
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

// More SSH event handlers
// can be defined in this trait
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

/// This struct is a convenience wrapper
/// around a russh client
/// that handles the input/output event loop
pub struct Session {
    session: russh::client::Handle<SshClient>,
}

impl Session {
    #[instrument(skip(privkey))]
    async fn connect<T: ToSocketAddrs + Debug + Clone>(
        privkey: PrivateKey,
        addrs: T,
        timeout: Duration,
    ) -> Result<Self> {
        let config = russh::client::Config {
            keepalive_interval: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = SshClient {};

        let vsock_addr = VsockAddr::new(123, 22);
        let now = Instant::now();
        debug!("Connecting to SSH via vsock");
        let mut session = loop {
            let stream = match VsockStream::connect(vsock_addr).await {
                Ok(stream) => stream,
                Err(ref e) if e.raw_os_error() == Some(19) => {
                    // This is "No such device" but for some reason Rust doesn't have an IO
                    // ErrorKind for it. Meh.
                    continue;
                }
                Err(ref e) => match e.kind() {
                    ErrorKind::TimedOut
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset => continue,
                    e => {
                        error!("Unhandled error occured: {e}");
                        bail!("Unknown error");
                    }
                },
            };
            match russh::client::connect_stream(config.clone(), stream, sh.clone()).await {
                Ok(x) => break x,
                Err(russh::Error::IO(ref e)) => {
                    match e.kind() {
                        // The VM is still booting at this point so we're just ignoring these errors
                        // for some time.
                        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
                            if now.elapsed() > timeout {
                                error!("Reached timeout trying to connect to virtual machine via SSH, aborting");
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
                        error!("Reached timeout trying to connect to virtual machine via SSH, aborting");
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

        Ok(Self { session })
    }

    #[instrument(skip(self))]
    async fn call(&mut self, env: Vec<EnvVar>, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // This example doesn't terminal resizing after the connection is established
        let (w, h) = termion::terminal_size()?;

        // Request an interactive PTY from the server
        channel
            .request_pty(
                true,
                &env::var("TERM").unwrap_or("xterm-256color".into()),
                w as u32,
                h as u32,
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

/// Connect SSH
#[instrument(skip(qemu_cancellation_token, ssh_cancellation_token, ssh_privkey))]
pub async fn connect_ssh(
    qemu_cancellation_token: CancellationToken,
    ssh_cancellation_token: CancellationToken,
    ssh_privkey: String,
    ssh_timeout: Duration,
    env: Vec<EnvVar>,
    args: Vec<String>,
) -> Result<()> {
    let privkey = PrivateKey::from_openssh(ssh_privkey)?;

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(privkey, ("localhost", 2222), ssh_timeout)
        .await
        .inspect_err(|_| {
            qemu_cancellation_token.cancel();
        })?;
    info!("Connected");

    let code = {
        // We're using `termion` to put the terminal into raw mode, so that we can
        // display the output of interactive applications correctly
        let _raw_term = std::io::stdout().into_raw_mode()?;

        let escaped_args = &args
            .into_iter()
            .map(|x| shell_escape::escape(x.into())) // arguments are escaped manually since the SSH protocol doesn't support quoting
            .collect::<Vec<_>>()
            .join(" ");
        let ssh_output = tokio::select! {
            _ = ssh_cancellation_token.cancelled() => {
                debug!("SSH task was cancelled");
                return Ok(())
            }
            val = ssh.call(env, escaped_args) => {
                val
            }
        };
        qemu_cancellation_token.cancel();
        ssh_output?
    };

    info!("Exit code: {:?}", code);
    qemu_cancellation_token.cancel();
    ssh.close().await?;
    Ok(())
}
