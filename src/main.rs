mod broker;
mod manifest;
mod vault;

use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use manifest::{Manifest, ProfileManifest, parse_cli_binding};
use vault::{Vault, VaultSecret, default_vault_path};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "no-clone",
    version,
    about = "Use secrets without copying them into the agent's view"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the encrypted local vault.
    Init,
    /// Change the vault's master password.
    #[command(alias = "passwd")]
    ChangePassword,
    /// Manage named secret profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Manage secrets inside profiles.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Explicitly unlock one or more profiles in the background broker.
    Unlock(UnlockArgs),
    /// Lock selected profiles, or all profiles when none are named.
    Lock(LockArgs),
    /// Show profiles currently held by the broker.
    Status,
    /// Run a command with bindings supplied by a repository manifest or CLI flags.
    Run(RunArgs),
    /// Internal foreground broker entry point.
    #[command(hide = true)]
    Broker {
        #[arg(long)]
        foreground: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Create a profile.
    Create(ProfileCreateArgs),
    /// List profiles without revealing secrets.
    List,
    /// Delete a profile and all of its secrets.
    Delete(ProfileNameArgs),
    /// Render a profile as plaintext dotenv, JSON, or YAML.
    Render(ProfileRenderArgs),
    /// Export a profile as an encrypted bundle.
    Export(ProfileExportArgs),
    /// Import an encrypted profile bundle.
    Import(ProfileImportArgs),
}

#[derive(Debug, Args)]
struct ProfileCreateArgs {
    /// Profile name used by repository manifests.
    name: String,
    /// Default unlock lifetime in seconds.
    #[arg(long, default_value_t = 1800)]
    ttl: i64,
}

#[derive(Debug, Args)]
struct ProfileNameArgs {
    /// Profile name.
    name: String,
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// Create or replace a secret without printing its value.
    #[command(alias = "add")]
    Set(SecretSetArgs),
    /// List secret names without revealing values.
    List(ProfileNameArgs),
    /// Delete a secret.
    Delete(SecretNameArgs),
    /// Explicitly print one secret after a fresh vault-password prompt.
    Print(SecretNameArgs),
}

#[derive(Debug, Args)]
struct SecretSetArgs {
    /// Profile that owns the secret.
    profile: String,
    /// Secret name referenced by manifests.
    name: String,
    /// Read the value from a hidden interactive prompt.
    #[arg(long, conflicts_with = "from_file")]
    prompt: bool,
    /// Import the value as bytes from a user-owned file.
    #[arg(long, value_name = "PATH", conflicts_with = "prompt")]
    from_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SecretNameArgs {
    /// Profile that owns the secret.
    profile: String,
    /// Secret name.
    name: String,
}

#[derive(Debug, Args)]
struct ProfileRenderArgs {
    /// Profile to render.
    name: String,
    /// Plaintext output format.
    #[arg(long, value_enum)]
    format: RenderFormat,
    /// Write the rendered output to this path.
    #[arg(long, value_name = "PATH", conflicts_with = "stdout")]
    output: Option<PathBuf>,
    /// Write the rendered output to standard output.
    #[arg(long, conflicts_with = "output")]
    stdout: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RenderFormat {
    Dotenv,
    Json,
    Yaml,
}

#[derive(Debug, Args)]
struct ProfileExportArgs {
    /// Profile to export.
    name: String,
    /// Destination encrypted bundle path.
    #[arg(long, value_name = "PATH", required = true)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ProfileImportArgs {
    /// Source encrypted profile bundle.
    bundle: PathBuf,
    /// Name for the imported profile. Defaults to the bundle's profile name.
    #[arg(long = "as", value_name = "PROFILE")]
    as_name: Option<String>,
}

#[derive(Debug, Args)]
struct UnlockArgs {
    /// Profiles to load into the broker's memory.
    #[arg(required = true, value_name = "PROFILE")]
    profiles: Vec<String>,
    /// Override the configured profile lifetime for this unlock session.
    #[arg(long, value_name = "SECONDS")]
    ttl: Option<i64>,
    /// Require the vault password before every run using these profiles.
    #[arg(long)]
    zero_trust: bool,
}

#[derive(Debug, Args)]
struct LockArgs {
    /// Profiles to lock. With no names, lock every active profile.
    #[arg(value_name = "PROFILE")]
    profiles: Vec<String>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Profile used with direct --bind options.
    #[arg(value_name = "PROFILE", conflicts_with = "manifest")]
    profile: Option<String>,
    /// Repository manifest describing profiles and transports.
    #[arg(long, value_name = "PATH", conflicts_with = "profile")]
    manifest: Option<PathBuf>,
    /// Direct binding in SECRET=stdin, SECRET=env:NAME, or SECRET=fd:NUMBER form.
    #[arg(long = "bind", value_name = "SECRET=TRANSPORT[:TARGET]")]
    bindings: Vec<String>,
    /// Target command, introduced by --.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => init_vault(),
        Command::ChangePassword => change_password(),
        Command::Profile { command } => profile_command(command),
        Command::Secret { command } => secret_command(command),
        Command::Unlock(args) => unlock_command(args),
        Command::Lock(args) => lock_command(args),
        Command::Status => status_command(),
        Command::Run(args) => run_command(args),
        Command::Broker { foreground } => {
            if !foreground {
                bail!("the broker command is for internal use");
            }
            broker::run_foreground()
        }
    }
}

fn init_vault() -> Result<()> {
    let path = default_vault_path()?;
    if path.exists() {
        bail!("vault already exists at {}", path.display());
    }

    let password = prompt_new_password()?;
    let vault = Vault::create(&path, &password)?;

    println!("Initialized encrypted vault.");
    println!("Vault: {}", vault.path().display());
    Ok(())
}

fn change_password() -> Result<()> {
    let path = default_vault_path()?;
    if !path.exists() {
        bail!("vault not initialized; run `no-clone init` first");
    }

    let current_password = prompt_password("Current vault password: ")?;
    let mut vault = Vault::open(&path, &current_password)?;
    let new_password = prompt_new_password_with("New vault password")?;
    vault.change_password(&new_password)?;
    drop(vault);

    // Verify the key persisted to disk before reporting success.
    drop(Vault::open(&path, &new_password)?);
    println!("Changed vault master password.");
    Ok(())
}

fn profile_command(command: ProfileCommand) -> Result<()> {
    match command {
        ProfileCommand::Create(args) => {
            validate_name(&args.name, "profile")?;
            if args.ttl <= 0 {
                bail!("profile TTL must be greater than zero");
            }

            let mut vault = open_vault()?;
            vault.create_profile(&args.name, args.ttl)?;
            println!("Created profile '{}'.", args.name);
            Ok(())
        }
        ProfileCommand::List => {
            let vault = open_vault()?;
            let profiles = vault.list_profiles()?;

            if profiles.is_empty() {
                println!("No profiles found.");
                return Ok(());
            }

            println!("PROFILE\tSECRETS\tTTL_SECONDS");
            for profile in profiles {
                println!(
                    "{}\t{}\t{}",
                    profile.name, profile.secret_count, profile.ttl_seconds
                );
            }
            Ok(())
        }
        ProfileCommand::Delete(args) => {
            validate_name(&args.name, "profile")?;
            let mut vault = open_vault()?;
            vault.delete_profile(&args.name)?;
            println!("Deleted profile '{}'.", args.name);
            Ok(())
        }
        ProfileCommand::Render(args) => render_profile(args),
        ProfileCommand::Export(args) => export_profile(args),
        ProfileCommand::Import(args) => import_profile(args),
    }
}

fn secret_command(command: SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Set(args) => {
            validate_name(&args.profile, "profile")?;
            validate_name(&args.name, "secret")?;

            let value: Zeroizing<Vec<u8>> = match (args.prompt, args.from_file) {
                (true, None) => {
                    prompt_secret(&format!("Value for {}/{}", args.profile, args.name))?
                }
                (false, Some(path)) => {
                    Zeroizing::new(std::fs::read(&path).with_context(|| {
                        format!("failed to read secret file {}", path.display())
                    })?)
                }
                (false, None) => bail!("provide either --prompt or --from-file"),
                (true, Some(_)) => unreachable!("clap enforces mutually exclusive arguments"),
            };

            let mut vault = open_vault()?;
            vault.put_secret(&args.profile, &args.name, &value)?;
            println!("Stored secret '{}/{}'.", args.profile, args.name);
            Ok(())
        }
        SecretCommand::List(args) => {
            validate_name(&args.name, "profile")?;
            let vault = open_vault()?;
            let secrets = vault.list_secrets(&args.name)?;

            if secrets.is_empty() {
                println!("No secrets found in profile '{}'.", args.name);
                return Ok(());
            }

            println!("PROFILE\tSECRET\tBYTES");
            for secret in secrets {
                println!("{}\t{}\t{}", args.name, secret.name, secret.byte_len);
            }
            Ok(())
        }
        SecretCommand::Delete(args) => {
            validate_name(&args.profile, "profile")?;
            validate_name(&args.name, "secret")?;
            let mut vault = open_vault()?;
            vault.delete_secret(&args.profile, &args.name)?;
            println!("Deleted secret '{}/{}'.", args.profile, args.name);
            Ok(())
        }
        SecretCommand::Print(args) => print_secret(args),
    }
}

fn render_profile(args: ProfileRenderArgs) -> Result<()> {
    validate_name(&args.name, "profile")?;
    if args.output.is_none() && !args.stdout {
        bail!("choose either --output PATH or --stdout");
    }

    let vault = open_vault()?;
    let (_, secrets) = vault.load_profile(&args.name)?;
    let values = secret_text_map(secrets)?;
    let rendered = match args.format {
        RenderFormat::Dotenv => render_dotenv(&values)?,
        RenderFormat::Json => serde_json::to_string_pretty(&values)? + "\n",
        RenderFormat::Yaml => serde_yaml::to_string(&values)?,
    };

    if let Some(path) = args.output {
        write_protected_output(&path, rendered.as_bytes())?;
        println!("Rendered profile '{}' to {}.", args.name, path.display());
    } else {
        std::io::stdout().write_all(rendered.as_bytes())?;
    }
    Ok(())
}

fn print_secret(args: SecretNameArgs) -> Result<()> {
    validate_name(&args.profile, "profile")?;
    validate_name(&args.name, "secret")?;
    let vault = open_vault()?;
    let secret = vault.get_secret(&args.profile, &args.name)?;
    std::io::stdout().write_all(&secret.value)?;
    std::io::stdout().flush()?;
    Ok(())
}

fn export_profile(args: ProfileExportArgs) -> Result<()> {
    validate_name(&args.name, "profile")?;
    let source = open_vault()?;
    let (ttl_seconds, secrets) = source.load_profile(&args.name)?;
    let bundle_password = prompt_new_password_with("Create bundle password")?;

    let temporary_directory =
        tempfile::tempdir().context("failed to create temporary bundle directory")?;
    let bundle_path = temporary_directory.path().join("profile.db");
    let mut bundle = Vault::create(&bundle_path, &bundle_password)?;
    bundle.create_profile(&args.name, ttl_seconds)?;
    for secret in secrets {
        bundle.put_secret(&args.name, &secret.name, &secret.value)?;
    }
    drop(bundle);

    fs::copy(&bundle_path, &args.output).with_context(|| {
        format!(
            "failed to write encrypted profile bundle {}",
            args.output.display()
        )
    })?;
    restrict_output_permissions(&args.output)?;
    println!(
        "Exported encrypted profile '{}' to {}.",
        args.name,
        args.output.display()
    );
    Ok(())
}

fn import_profile(args: ProfileImportArgs) -> Result<()> {
    if !args.bundle.exists() {
        bail!("bundle does not exist: {}", args.bundle.display());
    }

    let bundle_password = prompt_password("Bundle password: ")?;
    let bundle = Vault::open(&args.bundle, &bundle_password)?;
    let profiles = bundle.list_profiles()?;
    if profiles.len() != 1 {
        bail!("profile bundle must contain exactly one profile");
    }
    let source_name = profiles[0].name.clone();
    let target_name = args.as_name.unwrap_or(source_name.clone());
    validate_name(&target_name, "profile")?;
    let (ttl_seconds, secrets) = bundle.load_profile(&source_name)?;
    drop(bundle);

    let mut vault = open_vault()?;
    vault.create_profile(&target_name, ttl_seconds)?;
    for secret in secrets {
        vault.put_secret(&target_name, &secret.name, &secret.value)?;
    }
    println!("Imported encrypted profile as '{}'.", target_name);
    Ok(())
}

fn secret_text_map(secrets: Vec<VaultSecret>) -> Result<BTreeMap<String, String>> {
    secrets
        .into_iter()
        .map(|secret| {
            let value = String::from_utf8(secret.value.clone())
                .with_context(|| format!("secret '{}' is not valid UTF-8", secret.name))?;
            Ok((secret.name.clone(), value))
        })
        .collect()
}

fn render_dotenv(values: &BTreeMap<String, String>) -> Result<String> {
    let mut used_names = HashSet::new();
    let mut output = String::new();
    for (name, value) in values {
        let environment_name = dotenv_name(name)?;
        if !used_names.insert(environment_name.clone()) {
            bail!("secret names collide after dotenv conversion: '{name}'");
        }
        output.push_str(&environment_name);
        output.push_str("=\"");
        output.push_str(&dotenv_escape(value)?);
        output.push_str("\"\n");
    }
    Ok(output)
}

fn dotenv_name(name: &str) -> Result<String> {
    let mut output = String::new();
    let mut previous_underscore = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_uppercase());
            previous_underscore = false;
        } else if !previous_underscore {
            output.push('_');
            previous_underscore = true;
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
    if output.is_empty() {
        bail!("secret name '{name}' cannot be converted to a dotenv variable");
    }
    if output.as_bytes()[0].is_ascii_digit() {
        output.insert(0, '_');
    }
    Ok(output)
}

fn dotenv_escape(value: &str) -> Result<String> {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            character if character.is_control() => {
                bail!("secret contains an unsupported control character for dotenv output")
            }
            character => escaped.push(character),
        }
    }
    Ok(escaped)
}

fn write_protected_output(path: &Path, contents: &[u8]) -> Result<()> {
    if path.exists() {
        restrict_output_permissions(path)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    restrict_output_permissions(path)?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush {}", path.display()))
}

fn restrict_output_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn unlock_command(args: UnlockArgs) -> Result<()> {
    for profile in &args.profiles {
        validate_name(profile, "profile")?;
    }
    let password = prompt_password("Vault password: ")?;
    broker::unlock(args.profiles.clone(), args.ttl, args.zero_trust, password)?;
    if args.zero_trust {
        println!(
            "Unlocked zero-trust profile{}: {}.",
            plural(args.profiles.len()),
            args.profiles.join(", ")
        );
    } else {
        println!(
            "Unlocked profile{}: {}.",
            plural(args.profiles.len()),
            args.profiles.join(", ")
        );
    }
    Ok(())
}

fn lock_command(args: LockArgs) -> Result<()> {
    for profile in &args.profiles {
        validate_name(profile, "profile")?;
    }
    broker::lock(args.profiles.clone())?;
    if args.profiles.is_empty() {
        println!("Locked all profiles.");
    } else {
        println!(
            "Locked profile{}: {}.",
            plural(args.profiles.len()),
            args.profiles.join(", ")
        );
    }
    Ok(())
}

fn status_command() -> Result<()> {
    let profiles = broker::status()?;
    if profiles.is_empty() {
        println!("No profiles are unlocked.");
        return Ok(());
    }

    println!("PROFILE\tSTATUS\tAUTH\tEXPIRES");
    for profile in profiles {
        println!(
            "{}\tunlocked\t{}\t{}",
            profile.name,
            if profile.zero_trust {
                "zero-trust"
            } else {
                "standard"
            },
            remaining_time(profile.expires_at)?
        );
    }
    Ok(())
}

fn run_command(args: RunArgs) -> Result<()> {
    let manifest = match (args.manifest, args.profile, args.bindings) {
        (Some(path), None, bindings) if bindings.is_empty() => Manifest::read(&path)?,
        (None, Some(profile), bindings) if !bindings.is_empty() => {
            validate_name(&profile, "profile")?;
            let mut secrets = BTreeMap::new();
            for binding in bindings {
                let (name, binding) = parse_cli_binding(&binding)?;
                if secrets.insert(name.clone(), binding).is_some() {
                    bail!("secret '{profile}/{name}' is bound more than once");
                }
            }
            Manifest {
                version: 1,
                profiles: BTreeMap::from([(profile, ProfileManifest { secrets })]),
            }
        }
        (Some(_), _, _) => bail!("--manifest cannot be combined with a profile or --bind"),
        (None, _, _) => bail!("provide --manifest, or a profile together with at least one --bind"),
    };

    let command = args.command;
    let first_result = broker::run(manifest.clone(), command.clone(), None)?;
    let result = match first_result {
        broker::RunOutcome::Completed(result) => result,
        broker::RunOutcome::PasswordRequired { profiles } => {
            println!(
                "Zero-trust authorization required for profile{}: {}.",
                plural(profiles.len()),
                profiles.join(", ")
            );
            println!("Command: {}", command.join(" "));
            let password = prompt_password("Vault password: ")?;
            match broker::run(manifest, command, Some(password))? {
                broker::RunOutcome::Completed(result) => result,
                broker::RunOutcome::PasswordRequired { .. } => {
                    bail!("run authorization was not accepted")
                }
            }
        }
    };
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    if result.code != 0 {
        process::exit(result.code);
    }
    Ok(())
}

fn open_vault() -> Result<Vault> {
    let path = default_vault_path()?;
    if !path.exists() {
        bail!("vault not initialized; run `no-clone init` first");
    }

    let password = prompt_password("Vault password: ")?;
    Vault::open(&path, &password)
}

fn prompt_new_password() -> Result<Zeroizing<String>> {
    prompt_new_password_with("Create vault password")
}

fn prompt_new_password_with(label: &str) -> Result<Zeroizing<String>> {
    let password = prompt_password(&format!("{label}: "))?;
    if password.is_empty() {
        bail!("vault password cannot be empty");
    }

    let confirmation = prompt_password(&format!("Confirm {label}: "))?;
    if password != confirmation {
        bail!("passwords do not match");
    }

    Ok(password)
}

fn prompt_secret(label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let value = rpassword::prompt_password(format!("{label}: "))?;
    if value.is_empty() {
        bail!("secret value cannot be empty");
    }
    Ok(Zeroizing::new(value.into_bytes()))
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn validate_name(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        bail!("{kind} name cannot be empty");
    }
    if name.len() > 128 {
        bail!("{kind} name is too long");
    }
    if name == "." || name == ".." || name.chars().any(char::is_control) {
        bail!("invalid {kind} name");
    }
    Ok(())
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn remaining_time(expires_at: i64) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64;
    let seconds = expires_at.saturating_sub(now);
    let minutes = seconds / 60;
    let seconds = seconds % 60;
    Ok(if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_names_are_normalized() {
        assert_eq!(
            dotenv_name("database-password").unwrap(),
            "DATABASE_PASSWORD"
        );
        assert_eq!(dotenv_name("tls.cert").unwrap(), "TLS_CERT");
        assert_eq!(dotenv_name("2fa-token").unwrap(), "_2FA_TOKEN");
    }

    #[test]
    fn dotenv_collisions_are_rejected() {
        let values = BTreeMap::from([
            (String::from("database-password"), String::from("one")),
            (String::from("database_password"), String::from("two")),
        ]);
        assert!(render_dotenv(&values).is_err());
    }
}
