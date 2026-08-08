use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::validate_name;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub profiles: BTreeMap<String, ProfileManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManifest {
    pub secrets: BTreeMap<String, Binding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub transport: Transport,
    #[serde(default)]
    pub target: Option<Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Stdin,
    Env,
    Fd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Target {
    Text(String),
    Number(i64),
}

impl Manifest {
    pub fn read(path: &Path) -> Result<Self> {
        let contents = fs::read(path)
            .with_context(|| format!("failed to read manifest {}", path.display()))?;
        let manifest: Self = serde_yaml::from_slice(&contents)
            .with_context(|| format!("failed to parse manifest {}", path.display()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported manifest version {}; expected 1", self.version);
        }
        if self.profiles.is_empty() {
            bail!("manifest must contain at least one profile");
        }

        for (profile, profile_manifest) in &self.profiles {
            validate_name(profile, "profile")?;
            if profile_manifest.secrets.is_empty() {
                bail!("profile '{profile}' must contain at least one secret binding");
            }
            for (secret, binding) in &profile_manifest.secrets {
                validate_name(secret, "secret")?;
                binding.validate(profile, secret)?;
            }
        }
        Ok(())
    }
}

impl Binding {
    pub fn validate(&self, profile: &str, secret: &str) -> Result<()> {
        match self.transport {
            Transport::Stdin => {
                if self.target.is_some() {
                    bail!("binding '{profile}/{secret}' does not accept a stdin target");
                }
            }
            Transport::Env => {
                let Some(Target::Text(target)) = &self.target else {
                    bail!("binding '{profile}/{secret}' requires a text environment target");
                };
                if target.is_empty() {
                    bail!("binding '{profile}/{secret}' has an empty environment target");
                }
                if target.bytes().any(|byte| byte == 0 || byte == b'=') {
                    bail!("binding '{profile}/{secret}' has an invalid environment target");
                }
            }
            Transport::Fd => {
                let Some(target) = &self.target else {
                    bail!("binding '{profile}/{secret}' requires a file descriptor target");
                };
                let number = target_as_fd(target).with_context(|| {
                    format!("binding '{profile}/{secret}' has an invalid file descriptor")
                })?;
                if number < 3 {
                    bail!("binding '{profile}/{secret}' must use file descriptor 3 or higher");
                }
            }
        }
        Ok(())
    }
}

pub fn target_as_fd(target: &Target) -> Result<i32> {
    let value = match target {
        Target::Number(value) => *value,
        Target::Text(value) => value
            .parse::<i64>()
            .with_context(|| format!("'{value}' is not a file descriptor number"))?,
    };
    i32::try_from(value).context("file descriptor is outside the supported range")
}

pub fn parse_cli_binding(spec: &str) -> Result<(String, Binding)> {
    let (secret, delivery) = spec
        .split_once('=')
        .with_context(|| format!("invalid binding '{spec}'; expected SECRET=TRANSPORT[:TARGET]"))?;
    validate_name(secret, "secret")?;

    let (transport, target) = delivery
        .split_once(':')
        .map_or((delivery, None), |(transport, target)| {
            (transport, Some(target.to_owned()))
        });
    let binding = match transport {
        "stdin" if target.is_none() => Binding {
            transport: Transport::Stdin,
            target: None,
        },
        "env" => Binding {
            transport: Transport::Env,
            target: Some(Target::Text(
                target.context("env bindings require a target name")?,
            )),
        },
        "fd" => Binding {
            transport: Transport::Fd,
            target: Some(Target::Text(
                target.context("fd bindings require a target number")?,
            )),
        },
        _ => bail!("invalid binding '{spec}'; use stdin, env:NAME, or fd:NUMBER"),
    };

    binding.validate("<cli>", secret)?;
    Ok((secret.to_owned(), binding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_nested_multi_profile_manifest() {
        let manifest: Manifest = serde_yaml::from_str(
            "version: 1\nprofiles:\n  production:\n    secrets:\n      token:\n        transport: env\n        target: APP_TOKEN\n  registry:\n    secrets:\n      password:\n        transport: fd\n        target: 3\n",
        )
        .unwrap();

        manifest.validate().unwrap();
        assert_eq!(manifest.profiles.len(), 2);
        assert!(matches!(
            manifest.profiles["registry"].secrets["password"].target,
            Some(Target::Number(3))
        ));
    }

    #[test]
    fn rejects_invalid_transport_targets() {
        let missing_env_target = Binding {
            transport: Transport::Env,
            target: None,
        };
        assert!(missing_env_target.validate("production", "token").is_err());

        let low_fd = Binding {
            transport: Transport::Fd,
            target: Some(Target::Number(2)),
        };
        assert!(low_fd.validate("production", "token").is_err());
    }

    #[test]
    fn parses_direct_binding_syntax() {
        let (name, binding) = parse_cli_binding("deploy-token=env:APP_TOKEN").unwrap();
        assert_eq!(name, "deploy-token");
        assert!(matches!(binding.transport, Transport::Env));

        let (name, binding) = parse_cli_binding("tls-cert=fd:3").unwrap();
        assert_eq!(name, "tls-cert");
        assert!(matches!(binding.target, Some(Target::Text(ref value)) if value == "3"));
    }
}
