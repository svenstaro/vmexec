use std::fmt::Debug;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::{env, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use anyhow::{bail, Result};
use async_trait::async_trait;
use russh::{keys::key::PrivateKeyWithHashAlg, ChannelMsg, Disconnect};
use ssh_key::private::Ed25519Keypair;
use ssh_key::PrivateKey;
use termion::raw::IntoRawMode;
use tokio::time::Instant;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::ToSocketAddrs,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

#[derive(Clone, Debug)]
pub struct PersistedSshKeypair {
    pub pubkey_str: String,
    pub pubkey_path: PathBuf,
    pub privkey_str: String,
    pub privkey_path: PathBuf,
}

/// Create SSH key to be used with the virtual machine
#[tracing::instrument]
pub async fn create_ssh_key(tmpdir: &Path) -> Result<PersistedSshKeypair> {
    let privkey_path = tmpdir.join("id_ed25519");
    let pubkey_path = privkey_path.with_extension("pub");

    let ed25519_keypair = Ed25519Keypair::random(&mut ssh_key::rand_core::OsRng);

    let pubkey_openssh = ssh_key::PublicKey::from(ed25519_keypair.public).to_openssh()?;
    debug!("Writing SSH public key to {pubkey_path:?}");
    fs::write(&pubkey_path, &pubkey_openssh).await?;

    let privkey_openssh = ssh_key::PrivateKey::from(ed25519_keypair)
        .to_openssh(ssh_key::LineEnding::default())?
        .to_string();
    debug!("Writing SSH private key to {privkey_path:?}");

    fs::write(&privkey_path, &privkey_openssh).await?;
    let mut perms = fs::metadata(&privkey_path).await?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&privkey_path, perms).await?;

    let keypair = PersistedSshKeypair {
        pubkey_str: pubkey_openssh,
        pubkey_path,
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
#[async_trait]
impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
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
    #[tracing::instrument(skip(privkey))]
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

        let now = Instant::now();
        debug!("Connecting to SSH");

        let mut session = loop {
            match russh::client::connect(config.clone(), addrs.clone(), sh.clone()).await {
                Ok(x) => break x,
                Err(russh::Error::IO(ref e)) => match e.kind() {
                    // The VM is still booting at this point so we're just ignoring these errors
                    // for some time.
                    ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
                        if now.elapsed() > timeout {
                            dbg!(e);
                            bail!("Timeout");
                        }
                    }
                    e => panic!("{}", e),
                },
                Err(e) => {
                    continue;
                    dbg!(e);
                    bail!("somethings fcuked");
                }
            }
        };
        debug!("Authenticating via SSH");

        // use publickey authentication
        let auth_res = session
            .authenticate_publickey("root", PrivateKeyWithHashAlg::new(Arc::new(privkey), None)?)
            .await?;

        if !auth_res {
            anyhow::bail!("Authentication (with publickey) failed");
        }

        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // This example doesn't terminal resizing after the connection is established
        let (w, h) = termion::terminal_size()?;

        // Request an interactive PTY from the server
        channel
            .request_pty(
                false,
                &env::var("TERM").unwrap_or("xterm-256color".into()),
                w as u32,
                h as u32,
                0,
                0,
                &[], // ideally you want to pass the actual terminal modes here
            )
            .await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
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

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

/// Connect SSH
#[tracing::instrument(skip(ssh_privkey))]
pub async fn connect_ssh(
    qemu_cancellation_token: CancellationToken,
    ssh_cancellation_token: CancellationToken,
    ssh_privkey: String,
    ssh_timeout: Duration,
    args: Vec<String>,
) -> Result<()> {
    let privkey = PrivateKey::from_openssh(ssh_privkey)?;

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(privkey, ("localhost", 2222), ssh_timeout).await?;
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
                bail!("Task was cancelled")
            }
            val = ssh.call(escaped_args) => {
                val
            }
        };
        qemu_cancellation_token.cancel();
        ssh_output?
    };

    println!("Exitcode: {:?}", code);
    qemu_cancellation_token.cancel();
    ssh.close().await?;
    Ok(())
}
