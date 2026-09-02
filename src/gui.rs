use std::io::{BufRead, BufReader, Write};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    broker,
    vault::{self, Vault},
};

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    Snapshot {
        password: Option<String>,
    },
    InitializeVault {
        password: String,
    },
    UnlockVault {
        password: String,
    },
    LockVault,
    ListSecrets {
        profile: String,
        password: String,
    },
    CreateProfile {
        name: String,
        ttl_seconds: i64,
        password: String,
    },
    DeleteProfile {
        name: String,
        password: String,
    },
    SetSecret {
        profile: String,
        name: String,
        value: String,
        password: String,
    },
    DeleteSecret {
        profile: String,
        name: String,
        password: String,
    },
    UnlockProfiles {
        profiles: Vec<String>,
        ttl_seconds: Option<i64>,
        zero_trust: bool,
        password: String,
    },
    LockProfiles {
        profiles: Vec<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Response {
    Snapshot { snapshot: Snapshot },
    Secrets { secrets: Vec<vault::SecretSummary> },
    Error { message: String },
}

#[derive(Debug, Serialize)]
struct Snapshot {
    vault_exists: bool,
    vault_path: String,
    session_unlocked: bool,
    profiles: Vec<vault::ProfileSummary>,
    active_profiles: Vec<broker::ProfileStatus>,
}

pub fn run() -> Result<()> {
    // Keep the GUI protocol on stdin/stdout, while the broker remains a
    // separate per-user process managed by the no-clone executable.
    broker::status()?;
    let stdin = std::io::stdin();
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for line in BufReader::new(stdin.lock()).lines() {
        let response = match line {
            Ok(line) => match serde_json::from_str::<Request>(&line) {
                Ok(request) => match handle(request) {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: format!("{error:#}"),
                    },
                },
                Err(error) => Response::Error {
                    message: format!("invalid GUI request: {error}"),
                },
            },
            Err(error) => Response::Error {
                message: format!("failed to read GUI request: {error}"),
            },
        };
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}

fn snapshot(password: Option<&str>) -> Result<Snapshot> {
    let path = vault::default_vault_path()?;
    let profiles = match password {
        Some(password) if path.exists() => Vault::open(&path, password)?.list_profiles()?,
        _ => Vec::new(),
    };
    Ok(Snapshot {
        vault_exists: path.exists(),
        vault_path: path.display().to_string(),
        session_unlocked: password.is_some(),
        profiles,
        active_profiles: broker::status()?,
    })
}

fn open(password: &str) -> Result<Vault> {
    let path = vault::default_vault_path()?;
    if !path.exists() {
        bail!("vault is not initialized");
    }
    Vault::open(&path, password)
}

fn handle(request: Request) -> Result<Response> {
    match request {
        Request::Snapshot { password } => Ok(Response::Snapshot {
            snapshot: snapshot(password.as_deref())?,
        }),
        Request::InitializeVault { password } => {
            let path = vault::default_vault_path()?;
            if path.exists() {
                bail!("vault already exists");
            }
            Vault::create(&path, &password)?;
            Ok(Response::Snapshot {
                snapshot: snapshot(Some(&password))?,
            })
        }
        Request::UnlockVault { password } => {
            open(&password)?;
            Ok(Response::Snapshot {
                snapshot: snapshot(Some(&password))?,
            })
        }
        Request::LockVault => {
            broker::lock(Vec::new())?;
            Ok(Response::Snapshot {
                snapshot: snapshot(None)?,
            })
        }
        Request::ListSecrets { profile, password } => Ok(Response::Secrets {
            secrets: open(&password)?.list_secrets(&profile)?,
        }),
        Request::CreateProfile {
            name,
            ttl_seconds,
            password,
        } => {
            let mut vault = open(&password)?;
            crate::validate_name(&name, "profile")?;
            if ttl_seconds <= 0 {
                bail!("profile TTL must be greater than zero");
            }
            vault.create_profile(&name, ttl_seconds)?;
            Ok(Response::Snapshot {
                snapshot: snapshot(Some(&password))?,
            })
        }
        Request::DeleteProfile { name, password } => {
            broker::lock(vec![name.clone()])?;
            let mut vault = open(&password)?;
            vault.delete_profile(&name)?;
            Ok(Response::Snapshot {
                snapshot: snapshot(Some(&password))?,
            })
        }
        Request::SetSecret {
            profile,
            name,
            value,
            password,
        } => {
            crate::validate_name(&name, "secret")?;
            if value.is_empty() {
                bail!("secret value cannot be empty");
            }
            let mut vault = open(&password)?;
            vault.put_secret(&profile, &name, value.as_bytes())?;
            Ok(Response::Secrets {
                secrets: vault.list_secrets(&profile)?,
            })
        }
        Request::DeleteSecret {
            profile,
            name,
            password,
        } => {
            let mut vault = open(&password)?;
            vault.delete_secret(&profile, &name)?;
            Ok(Response::Secrets {
                secrets: vault.list_secrets(&profile)?,
            })
        }
        Request::UnlockProfiles {
            profiles,
            ttl_seconds,
            zero_trust,
            password,
        } => {
            broker::unlock(
                profiles,
                ttl_seconds,
                zero_trust,
                Zeroizing::new(password.clone()),
            )?;
            Ok(Response::Snapshot {
                snapshot: snapshot(Some(&password))?,
            })
        }
        Request::LockProfiles { profiles } => {
            broker::lock(profiles)?;
            Ok(Response::Snapshot {
                snapshot: snapshot(None)?,
            })
        }
    }
}
