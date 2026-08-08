use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use interprocess::local_socket::{GenericNamespaced, ListenerOptions, Stream, prelude::*};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    manifest::{Binding, Manifest, Target, Transport, target_as_fd},
    vault::{Vault, VaultSecret, default_vault_path},
};

const BROKER_NAME_PREFIX: &str = "no-clone-broker";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    Unlock {
        profiles: Vec<String>,
        ttl_seconds: Option<i64>,
        zero_trust: bool,
        password: String,
    },
    Lock {
        profiles: Vec<String>,
    },
    Status,
    Run {
        manifest: Manifest,
        command: Vec<String>,
        cwd: std::path::PathBuf,
        password: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status {
        profiles: Vec<ProfileStatus>,
    },
    PasswordRequired {
        profiles: Vec<String>,
    },
    RunResult {
        code: i32,
        stdout: String,
        stderr: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileStatus {
    pub name: String,
    pub expires_at: i64,
    pub zero_trust: bool,
}

#[derive(Debug, Default)]
struct SessionState {
    profiles: HashMap<String, ActiveProfile>,
}

#[derive(Debug)]
struct ActiveProfile {
    expires_at: i64,
    zero_trust: bool,
    secrets: HashMap<String, Zeroizing<Vec<u8>>>,
}

#[cfg(unix)]
type SecretWriter = (std::fs::File, Zeroizing<Vec<u8>>);

pub fn unlock(
    profiles: Vec<String>,
    ttl_seconds: Option<i64>,
    zero_trust: bool,
    password: Zeroizing<String>,
) -> Result<()> {
    if profiles.is_empty() {
        bail!("provide at least one profile to unlock");
    }
    if let Some(ttl) = ttl_seconds
        && ttl <= 0
    {
        bail!("unlock TTL must be greater than zero");
    }

    ensure_running()?;
    let mut request = Request::Unlock {
        profiles,
        ttl_seconds,
        zero_trust,
        password: password.to_string(),
    };
    let response = send(&request);
    if let Request::Unlock { password, .. } = &mut request {
        password.zeroize();
    }
    let response = response?;
    expect_ok(response)
}

pub fn lock(profiles: Vec<String>) -> Result<()> {
    ensure_running()?;
    expect_ok(send(&Request::Lock { profiles })?)
}

pub fn status() -> Result<Vec<ProfileStatus>> {
    ensure_running()?;
    match send(&Request::Status)? {
        Response::Status { profiles } => Ok(profiles),
        response => unexpected_response(response),
    }
}

pub fn run(
    manifest: Manifest,
    command: Vec<String>,
    password: Option<Zeroizing<String>>,
) -> Result<RunOutcome> {
    if command.is_empty() {
        bail!("a command is required");
    }
    manifest.validate()?;
    ensure_running()?;

    let cwd = std::env::current_dir().context("could not determine the run working directory")?;
    let mut request = Request::Run {
        manifest,
        command,
        cwd,
        password: password
            .as_ref()
            .map(|password| password.as_str().to_owned()),
    };
    let response = send(&request);
    if let Request::Run {
        password: Some(password),
        ..
    } = &mut request
    {
        password.zeroize();
    }

    match response? {
        Response::RunResult {
            code,
            stdout,
            stderr,
        } => Ok(RunOutcome::Completed(RunResult {
            code,
            stdout,
            stderr,
        })),
        Response::PasswordRequired { profiles } => Ok(RunOutcome::PasswordRequired { profiles }),
        response => unexpected_response(response),
    }
}

#[derive(Debug)]
pub enum RunOutcome {
    Completed(RunResult),
    PasswordRequired { profiles: Vec<String> },
}

#[derive(Debug)]
pub struct RunResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_foreground() -> Result<()> {
    let name = broker_name()?;
    let listener = ListenerOptions::new()
        .name(name)
        .create_sync()
        .context("could not start the broker; another broker may already be running")?;
    let state = Arc::new(Mutex::new(SessionState::default()));
    let vault_path = default_vault_path()?;

    for connection in listener.incoming() {
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("broker connection failed: {error}");
                continue;
            }
        };
        if let Err(error) = authorize_peer(&connection) {
            eprintln!("broker rejected connection: {error}");
            continue;
        }
        let state = Arc::clone(&state);
        let vault_path = vault_path.clone();
        thread::spawn(move || handle_connection(connection, state, vault_path));
    }

    Ok(())
}

fn authorize_peer(connection: &Stream) -> Result<()> {
    #[cfg(unix)]
    {
        let credentials = connection
            .peer_creds()
            .context("could not inspect broker client credentials")?;
        let Some(peer_uid) = credentials.euid() else {
            bail!("broker client credentials did not include a user id");
        };
        let current_uid = unsafe { libc::geteuid() };
        if peer_uid != current_uid {
            bail!("broker accepts clients from the current user only");
        }
    }

    #[cfg(not(unix))]
    let _ = connection;

    Ok(())
}

fn handle_connection(
    connection: Stream,
    state: Arc<Mutex<SessionState>>,
    vault_path: std::path::PathBuf,
) {
    let mut connection = BufReader::new(connection);
    let mut line = Zeroizing::new(String::new());
    let response = match connection.read_line(&mut line) {
        Ok(0) => return,
        Ok(_) => match serde_json::from_str::<Request>(&line) {
            Ok(request) => dispatch(request, &state, &vault_path),
            Err(error) => Response::Error {
                message: format!("invalid broker request: {error}"),
            },
        },
        Err(error) => Response::Error {
            message: format!("failed to read broker request: {error}"),
        },
    };

    match serde_json::to_vec(&response) {
        Ok(mut encoded) => {
            encoded.push(b'\n');
            if let Err(error) = connection.get_mut().write_all(&encoded) {
                eprintln!("failed to write broker response: {error}");
            }
        }
        Err(error) => eprintln!("failed to encode broker response: {error}"),
    }
}

fn dispatch(
    request: Request,
    state: &Arc<Mutex<SessionState>>,
    vault_path: &std::path::Path,
) -> Response {
    let result = match request {
        Request::Unlock {
            profiles,
            ttl_seconds,
            zero_trust,
            password,
        } => unlock_profiles(
            state,
            vault_path,
            profiles,
            ttl_seconds,
            zero_trust,
            password,
        ),
        Request::Lock { profiles } => lock_profiles(state, &profiles),
        Request::Status => status_profiles(state),
        Request::Run {
            manifest,
            command,
            cwd,
            password,
        } => run_target(state, vault_path, manifest, command, &cwd, password),
    };

    match result {
        Ok(response) => response,
        Err(error) => Response::Error {
            message: format!("{error:#}"),
        },
    }
}

fn unlock_profiles(
    state: &Arc<Mutex<SessionState>>,
    vault_path: &std::path::Path,
    profiles: Vec<String>,
    ttl_override: Option<i64>,
    zero_trust: bool,
    password: String,
) -> Result<Response> {
    let password = Zeroizing::new(password);
    let vault = Vault::open(vault_path, &password)?;
    let now = unix_time()?;
    let mut loaded = BTreeMap::new();

    for profile in profiles {
        let (profile_ttl, secrets) = vault.load_profile(&profile)?;
        let secrets = secrets
            .into_iter()
            .map(|secret: VaultSecret| (secret.name.clone(), Zeroizing::new(secret.value.clone())))
            .collect();
        let ttl = ttl_override.unwrap_or(profile_ttl);
        loaded.insert(
            profile,
            ActiveProfile {
                expires_at: now.saturating_add(ttl),
                zero_trust,
                secrets,
            },
        );
    }

    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("broker state is unavailable"))?;
    purge_expired(&mut state, now);
    for (name, profile) in &mut loaded {
        if let Some(existing) = state.profiles.get(name)
            && existing.zero_trust
        {
            profile.zero_trust = true;
        }
    }
    state.profiles.extend(loaded);
    Ok(Response::Ok)
}

fn lock_profiles(state: &Arc<Mutex<SessionState>>, profiles: &[String]) -> Result<Response> {
    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("broker state is unavailable"))?;
    if profiles.is_empty() {
        state.profiles.clear();
    } else {
        for profile in profiles {
            state.profiles.remove(profile);
        }
    }
    Ok(Response::Ok)
}

fn status_profiles(state: &Arc<Mutex<SessionState>>) -> Result<Response> {
    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("broker state is unavailable"))?;
    purge_expired(&mut state, unix_time()?);
    let mut profiles = state
        .profiles
        .iter()
        .map(|(name, profile)| ProfileStatus {
            name: name.clone(),
            expires_at: profile.expires_at,
            zero_trust: profile.zero_trust,
        })
        .collect::<Vec<_>>();
    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(Response::Status { profiles })
}

fn run_target(
    state: &Arc<Mutex<SessionState>>,
    vault_path: &std::path::Path,
    manifest: Manifest,
    command: Vec<String>,
    cwd: &std::path::Path,
    password: Option<String>,
) -> Result<Response> {
    let now = unix_time()?;
    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("broker state is unavailable"))?;
    purge_expired(&mut state, now);

    let mut protected_profiles = Vec::new();
    for profile_name in manifest.profiles.keys() {
        let Some(active_profile) = state.profiles.get(profile_name) else {
            bail!(
                "profile '{profile_name}' is locked or expired; run no-clone unlock {profile_name} first"
            );
        };
        if active_profile.zero_trust {
            protected_profiles.push(profile_name.clone());
        }
    }
    if !protected_profiles.is_empty() {
        let Some(password) = password else {
            return Ok(Response::PasswordRequired {
                profiles: protected_profiles,
            });
        };
        let password = Zeroizing::new(password);
        Vault::open(vault_path, &password).context("vault password rejected")?;
    }

    let mut deliveries = Vec::new();
    for (profile_name, profile_manifest) in manifest.profiles {
        let Some(active_profile) = state.profiles.get(&profile_name) else {
            bail!(
                "profile '{profile_name}' is locked or expired; run no-clone unlock {profile_name} first"
            );
        };
        for (secret_name, binding) in profile_manifest.secrets {
            let Some(value) = active_profile.secrets.get(&secret_name) else {
                bail!("secret '{profile_name}/{secret_name}' does not exist");
            };
            deliveries.push((binding, Zeroizing::new(value.to_vec())));
        }
    }
    drop(state);

    let result = execute_target(&command, cwd, deliveries)?;
    Ok(Response::RunResult {
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

fn execute_target(
    command: &[String],
    cwd: &std::path::Path,
    deliveries: Vec<(Binding, Zeroizing<Vec<u8>>)>,
) -> Result<RunResult> {
    let mut target = Command::new(&command[0]);
    target.args(&command[1..]);
    target.current_dir(cwd);
    target.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut stdin_value = None;
    let mut fd_values = Vec::new();
    let mut env_targets = HashSet::new();

    for (binding, value) in deliveries {
        match binding.transport {
            Transport::Stdin => {
                if stdin_value.is_some() {
                    bail!("a run may contain only one stdin binding");
                }
                target.stdin(Stdio::piped());
                stdin_value = Some(value);
            }
            Transport::Env => {
                let Some(Target::Text(name)) = binding.target else {
                    bail!("environment binding is missing its target name");
                };
                if !env_targets.insert(name.clone()) {
                    bail!("environment target '{name}' is used more than once");
                }
                let value = String::from_utf8(value.to_vec()).with_context(|| {
                    format!("secret for environment target '{name}' is not UTF-8")
                })?;
                target.env(name, value);
            }
            Transport::Fd => {
                let Some(target_fd) = binding.target.as_ref().map(target_as_fd).transpose()? else {
                    bail!("file descriptor binding is missing its target number");
                };
                if fd_values.iter().any(|(fd, _)| *fd == target_fd) {
                    bail!("file descriptor target {target_fd} is used more than once");
                }
                fd_values.push((target_fd, value));
            }
        }
    }

    #[cfg(not(unix))]
    if !fd_values.is_empty() {
        bail!("fd transport is currently supported on Unix platforms only");
    }

    #[cfg(unix)]
    let (mut fd_writers, read_fds) = prepare_fd_pipes(&mut target, fd_values)?;

    let mut child = match target.spawn() {
        Ok(child) => child,
        Err(error) => {
            #[cfg(unix)]
            for read_fd in read_fds.iter().copied() {
                close_fd(read_fd);
            }
            return Err(error).context("failed to start target command");
        }
    };

    #[cfg(unix)]
    for read_fd in read_fds {
        close_fd(read_fd);
    }

    let stdin_writer = stdin_value.map(|value| {
        let mut stdin = child
            .stdin
            .take()
            .expect("stdin was configured when the binding was prepared");
        thread::spawn(move || -> Result<()> {
            stdin
                .write_all(&value)
                .context("failed to deliver secret on stdin")?;
            Ok(())
        })
    });

    let fd_writer_threads = {
        #[cfg(unix)]
        {
            fd_writers
                .drain(..)
                .map(|(mut writer, value)| {
                    thread::spawn(move || -> Result<()> {
                        writer
                            .write_all(&value)
                            .context("failed to deliver secret on file descriptor")?;
                        Ok(())
                    })
                })
                .collect::<Vec<_>>()
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    };

    let output = child
        .wait_with_output()
        .context("failed while waiting for target command")?;
    if let Some(writer) = stdin_writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("stdin delivery thread panicked"))??;
    }
    for writer in fd_writer_threads {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("file descriptor delivery thread panicked"))??;
    }

    Ok(RunResult {
        code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(unix)]
fn prepare_fd_pipes(
    target: &mut Command,
    values: Vec<(i32, Zeroizing<Vec<u8>>)>,
) -> Result<(Vec<SecretWriter>, Vec<i32>)> {
    use std::{fs::File, os::fd::FromRawFd, os::unix::process::CommandExt};

    let source_base = values
        .iter()
        .map(|(target_fd, _)| *target_fd)
        .max()
        .unwrap_or(99)
        .saturating_add(1)
        .max(100);
    let mut mappings = Vec::with_capacity(values.len());
    let mut writers = Vec::with_capacity(values.len());
    for (target_fd, value) in values {
        let mut pipe_fds = [0; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            close_fd(pipe_fds[0]);
            close_fd(pipe_fds[1]);
            return Err(std::io::Error::last_os_error()).context("failed to create secret pipe");
        }
        if let Err(error) = set_cloexec(pipe_fds[0]).and_then(|_| set_cloexec(pipe_fds[1])) {
            close_fd(pipe_fds[0]);
            close_fd(pipe_fds[1]);
            return Err(error);
        }

        let read_fd = unsafe { libc::fcntl(pipe_fds[0], libc::F_DUPFD, source_base) };
        if read_fd < 0 {
            close_fd(pipe_fds[0]);
            close_fd(pipe_fds[1]);
            return Err(std::io::Error::last_os_error()).context("failed to prepare secret pipe");
        }
        close_fd(pipe_fds[0]);
        let writer = unsafe { File::from_raw_fd(pipe_fds[1]) };
        mappings.push((target_fd, read_fd));
        writers.push((writer, value));
    }

    let child_mappings = mappings.clone();
    unsafe {
        target.pre_exec(move || {
            for (target_fd, read_fd) in &child_mappings {
                if libc::dup2(*read_fd, *target_fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (_, read_fd) in &child_mappings {
                close_fd(*read_fd);
            }
            Ok(())
        });
    }

    Ok((
        writers,
        mappings.into_iter().map(|(_, read_fd)| read_fd).collect(),
    ))
}

#[cfg(unix)]
fn close_fd(fd: i32) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

#[cfg(unix)]
fn set_cloexec(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to inspect secret pipe");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to protect secret pipe");
    }
    Ok(())
}

fn purge_expired(state: &mut SessionState, now: i64) {
    state.profiles.retain(|_, profile| profile.expires_at > now);
}

fn ensure_running() -> Result<()> {
    if try_connect().is_ok() {
        return Ok(());
    }

    let executable = std::env::current_exe().context("could not locate the no-clone executable")?;
    let mut broker = Command::new(executable);
    broker
        .args(["broker", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        broker.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    broker
        .spawn()
        .context("failed to start the background broker")?;

    for _ in 0..40 {
        if try_connect().is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!("broker did not become ready")
}

fn try_connect() -> Result<Stream> {
    Stream::connect(broker_name()?).context("broker is not running")
}

fn send(request: &Request) -> Result<Response> {
    let mut connection = try_connect()?;
    serde_json::to_writer(&mut connection, &request).context("failed to encode broker request")?;
    connection
        .write_all(b"\n")
        .context("failed to send broker request")?;
    let mut response = String::new();
    BufReader::new(connection)
        .read_line(&mut response)
        .context("failed to read broker response")?;
    serde_json::from_str(&response).context("invalid broker response")
}

fn expect_ok(response: Response) -> Result<()> {
    match response {
        Response::Ok => Ok(()),
        response => unexpected_response(response),
    }
}

fn unexpected_response<T>(response: Response) -> Result<T> {
    match response {
        Response::Error { message } => bail!(message),
        other => bail!("unexpected broker response: {other:?}"),
    }
}

fn broker_name() -> Result<interprocess::local_socket::Name<'static>> {
    let suffix = if cfg!(unix) {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid().to_string() }
        }
        #[cfg(not(unix))]
        {
            String::from("user")
        }
    } else {
        std::env::var("USERNAME")
            .unwrap_or_else(|_| String::from("user"))
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!("{BROKER_NAME_PREFIX}-{suffix}")
        .to_ns_name::<GenericNamespaced>()
        .context("could not create the broker IPC name")
}

fn unix_time() -> Result<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Binding, ProfileManifest};

    #[cfg(unix)]
    #[test]
    fn unlock_run_and_lock_lifecycle() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let vault_path = temporary_directory.path().join("vault.db");
        let mut vault = Vault::create(&vault_path, "test-password").unwrap();
        vault.create_profile("production", 300).unwrap();
        vault
            .put_secret("production", "token", b"secret-value")
            .unwrap();
        drop(vault);

        let state = Arc::new(Mutex::new(SessionState::default()));
        let unlock_response = dispatch(
            Request::Unlock {
                profiles: vec![String::from("production")],
                ttl_seconds: None,
                zero_trust: true,
                password: String::from("test-password"),
            },
            &state,
            &vault_path,
        );
        assert!(matches!(unlock_response, Response::Ok));

        let manifest = Manifest {
            version: 1,
            profiles: BTreeMap::from([(
                String::from("production"),
                ProfileManifest {
                    secrets: BTreeMap::from([(
                        String::from("token"),
                        Binding {
                            transport: Transport::Env,
                            target: Some(Target::Text(String::from("APP_TOKEN"))),
                        },
                    )]),
                },
            )]),
        };
        let authorization_response = dispatch(
            Request::Run {
                manifest: manifest.clone(),
                command: vec![String::from("/bin/true")],
                cwd: temporary_directory.path().to_path_buf(),
                password: None,
            },
            &state,
            &vault_path,
        );
        assert!(matches!(
            authorization_response,
            Response::PasswordRequired { profiles }
                if profiles == vec![String::from("production")]
        ));

        let run_response = dispatch(
            Request::Run {
                manifest,
                command: vec![
                    String::from("/bin/sh"),
                    String::from("-c"),
                    String::from("printf '%s' \"$APP_TOKEN\""),
                ],
                cwd: temporary_directory.path().to_path_buf(),
                password: Some(String::from("test-password")),
            },
            &state,
            &vault_path,
        );
        match run_response {
            Response::RunResult { code, stdout, .. } => {
                assert_eq!(code, 0);
                assert_eq!(stdout, "secret-value");
            }
            response => panic!("unexpected broker response: {response:?}"),
        }

        assert!(matches!(
            dispatch(
                Request::Lock {
                    profiles: vec![String::from("production")]
                },
                &state,
                &vault_path,
            ),
            Response::Ok
        ));
    }
}
