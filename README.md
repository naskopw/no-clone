# no-clone

### A local secret broker for AI-assisted command-line work

`no-clone` lets an agent run commands that need credentials without putting the credential values into the agent's context.

The user stores secrets in local profiles and explicitly unlocks the profiles needed for a task. A local broker then delivers selected secrets directly to the target process through stdin, file descriptors, or short-lived environment variables.

The agent works with names and operation results. It does not need to handle the secret values.

> **Status:** early implementation. The encrypted vault, profile and secret lifecycle, broker IPC, profile sessions, manifest-driven runs, transports, rendering, and encrypted profile transfer are implemented in this repository. The project is still pre-release and should not yet be treated as a production security product.

## The model

```text
user unlocks a profile
          ↓
encrypted vault → in-memory broker
                         ↓
                 target process
```

`no-clone` is built around four concepts:

- **Vault** — an encrypted SQLCipher database stored on the user's machine.
- **Profile** — a named group of secrets, such as `production` or `registry`.
- **Manifest** — a repository file that describes which profile secrets a command needs and how to deliver them.
- **Broker** — a per-user background process that holds unlocked secrets in memory and launches target commands.

The manifest describes what a project needs. It is not what unlocks a profile. Unlocking is always an explicit user action.

## Features

- Encrypted local storage with SQLCipher-backed SQLite.
- Cross-platform Rust application for Windows, macOS, and Linux.
- User-controlled profile unlocking and locking.
- Independent expiration for each unlocked profile.
- Optional zero-trust sessions requiring the vault password for every delivery.
- No automatic unlocking.
- Local background broker with protected cross-platform IPC.
- Multiple secret transports: stdin, file descriptors on Unix, and environment variables.
- Repository manifests with multiple profiles and secret bindings.
- User-authorized rendering to dotenv, JSON, and YAML.
- Encrypted profile import and export.
- No output redaction or post-delivery claims that the target cannot disclose its inputs.

## Typical workflow

### Set up the vault

```text
no-clone init
no-clone profile create production
no-clone profile create registry
```

Add secrets without displaying their values:

```text
no-clone secret set production deploy-token --prompt
no-clone secret set production database-password --prompt
no-clone secret set registry password --prompt
```

Inspect profiles and secret names safely:

```text
no-clone profile list
no-clone secret list production
no-clone status
```

### Define project bindings

A repository can contain a `.no-clone.yaml` file:

```yaml
version: 1

profiles:
  production:
    secrets:
      deploy-token:
        transport: env
        target: APP_TOKEN

      database-password:
        transport: fd
        target: 3

  registry:
    secrets:
      password:
        transport: env
        target: REGISTRY_PASSWORD
```

The manifest contains secret names and delivery instructions, never secret values. It is safe to keep with the project source, subject to normal review of project configuration.

### Unlock and run

The user unlocks the profiles in a separate terminal:

```text
no-clone unlock production registry
```

This starts the per-user broker if needed, prompts for the vault password, and loads the selected profiles into memory. The unlock command returns when the broker is ready.

For profiles that should require user authorization on every delivery:

```text
no-clone unlock production --zero-trust
```

Zero-trust profiles remain unlocked in memory, but every `run` that uses one requires the vault password again before the target starts. The run displays the profile names and command context before prompting. Agents must never provide this password.

The agent can then run the project command:

```text
no-clone run --manifest .no-clone.yaml -- ./deploy.sh
```

The broker checks that all referenced profiles are unlocked, creates the requested transports, launches `./deploy.sh`, and returns its output and exit status. The CLI process used by the agent never receives the secret values.

For a one-off command, bindings can be supplied directly:

```text
no-clone run production \
  --bind deploy-token=env:APP_TOKEN \
  --bind database-password=fd:3 \
  -- ./deploy.sh
```

When the task is finished:

```text
no-clone lock production registry
```

## Profiles expire independently

Each profile has its own unlock lifetime:

```text
PROFILE       STATUS       AUTH          EXPIRES
production    unlocked     zero-trust    24m 12s
registry      unlocked     standard      09m 12s
```

When a profile expires, the broker removes it from active memory and rejects new requests that need it. Expiration does not revoke a credential already delivered to a running target process.

`run` never unlocks a profile automatically. A locked or expired profile is an error until the user explicitly unlocks it again. A zero-trust profile additionally requires the vault password for each delivery.

## Secret transports

The manifest chooses the transport required by the target application.

| Transport | Use when |
| --- | --- |
| `stdin` | The application reads a credential from standard input. |
| `fd` | The application can read a dedicated inherited file descriptor; currently Unix-only. |
| `env` | The application requires a specific environment-variable name. |

Environment variables are scoped to the target process tree. They are never exported into the agent's shell.

## Plaintext rendering

Direct process delivery is the normal path. Rendering is an explicit user-authorized escape hatch for applications that need a file or for preparing configuration manually.

Rendering does not use a repository manifest:

```text
no-clone profile render production \
  --format dotenv \
  --output .env
```

Structured formats are also supported:

```text
no-clone profile render production \
  --format json \
  --output secrets.json

no-clone profile render production \
  --format yaml \
  --stdout
```

Rendering and single-secret reveal require the vault password again, even if the profile is already unlocked. Non-interactive rendering is rejected by default.

To intentionally reveal one raw secret:

```text
no-clone secret print production database-password
```

For dotenv output, names are converted best-effort:

```text
database-password → DATABASE_PASSWORD
tls.cert          → TLS_CERT
2fa-token         → _2FA_TOKEN
```

The conversion uppercases names, replaces non-alphanumeric characters with underscores, collapses repeated underscores, and prefixes names that begin with a digit. Invalid or colliding names cause the operation to fail.

Rendered files contain plaintext secrets. They should be protected, kept out of version control, and removed when no longer needed.

## Encrypted profile transfer

Profiles can be moved between trusted `no-clone` installations as encrypted bundles:

```text
no-clone profile export production \
  --output production.no-clone

no-clone profile import production.no-clone \
  --as production
```

Export asks for a new bundle password. Import asks for the bundle password and then the destination vault password. Profile bundles contain encrypted profile data and metadata. They do not contain repository manifests and are never printed as plaintext.

## Storage and broker

The vault is a SQLCipher-encrypted SQLite database. Plain SQLite is never used for secret storage.

The vault password is not stored. The broker opens the encrypted database after the user unlocks a profile and keeps the active profile data in memory until it is locked or expires.

The broker is a per-user background process, not a system-wide service. The CLI communicates with it through protected local IPC:

- Unix domain sockets on Linux and macOS;
- a protected named pipe on Windows.

If the broker exits, unlocked state is lost. No plaintext profile data is written to disk as part of the unlock session.

SQLCipher is bundled with the Rust application and opened with SQLCipher compatibility settings equivalent to version 4. The dependency is locked in `Cargo.lock` so vault files remain portable across supported builds.

## Security boundary

`no-clone` protects secrets from the agent until delivery to the target process. After delivery, the target application owns the responsibility for handling its inputs.

`no-clone` does not inspect, rewrite, or redact target stdout and stderr. If a target prints a secret, that output may be visible to the agent. Likewise, rendering a plaintext `.env` file intentionally places the secret where other processes can read it.

The tool is designed to prevent routine or accidental agent exposure. It is not a defense against a malicious target command or a malicious process with unrestricted access to the same operating-system account.

## Agent rules

Agents using `no-clone` should:

- use profile and secret names, never raw values;
- use the repository manifest for normal execution;
- never ask the user to paste a secret into chat;
- never read protected secret files directly;
- never place secrets in arguments, prompts, generated files, or shell history;
- never unlock profiles;
- never invoke plaintext rendering or reveal during normal execution;
- prefer stdin or file descriptors when supported;
- lock profiles or let them expire after the task.

The repository also ships an agent skill at [skills/no-clone/SKILL.md](skills/no-clone/SKILL.md). It teaches compatible agents to use manifests and `no-clone run` without requesting, reading, or printing secret values.

## Why the name?

The name is inspired by blind computation and the no-cloning theorem from quantum information science. In blind computation, one party provides private input to another party, which performs a computation without learning the underlying input. `no-clone` applies a similar idea to agent-driven workflows: the user owns the secret, the agent requests an operation by name, and the required process receives the value without the agent needing to copy it into its own context.

`no-clone` does not use quantum cryptography. The name describes the intended privacy boundary, not the underlying implementation.

## Current implementation status

The current prototype includes the core workflow described above. It is not yet a packaged release: installation/distribution, Windows-specific FD delivery, migration tooling, and a broader security audit still need to be completed.
