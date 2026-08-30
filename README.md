# no-clone

`no-clone` is a local secret broker for command-line automation. It lets a
command use credentials without putting their values in arguments, shell
history, or the process that requested the command.

The project is early-stage software. It has not had a full independent
security audit and should be evaluated carefully before use with production
credentials.

## How it works

Secrets are stored in an encrypted SQLCipher database. A user unlocks one or
more profiles, and the local broker keeps those profiles in memory for the
duration of the session. When a command runs, the broker delivers only the
secrets declared for that command.

- A **vault** stores encrypted profile data on the local machine.
- A **profile** groups related secrets, such as `production` or `registry`.
- A **manifest** describes the profiles, secret names, and transports required
  by a command.
- The **broker** manages unlocked profiles and launches commands with their
  credentials.

The manifest contains names and delivery instructions, never secret values.

## Installation

Install from a local checkout with Cargo:

```text
cargo install --path .
```

The resulting `no-clone` executable is installed in Cargo's binary directory.

## Quick start

Create a vault and a profile, then add secrets through hidden prompts:

```text
no-clone init
no-clone profile create production
no-clone secret set production deploy-token --prompt
no-clone secret set production database-password --prompt
```

Profiles and secret names can be listed without revealing their values:

```text
no-clone profile list
no-clone secret list production
no-clone status
```

Unlocking is an explicit user action. It starts the per-user broker when
needed and loads the selected profiles into memory:

```text
no-clone unlock production
```

A command can then use a repository manifest:

```text
no-clone run --manifest .no-clone.yaml -- ./deploy.sh
```

Lock profiles when the work is finished:

```text
no-clone lock production
```

Profiles can also be unlocked in zero-trust mode. In that mode, the vault
password is required again before each delivery:

```text
no-clone unlock production --zero-trust
```

## Manifests

A `.no-clone.yaml` file declares how named secrets should reach the target
process:

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

The supported transports are:

| Transport | Use when |
| --- | --- |
| `stdin` | The command reads a credential from standard input. |
| `fd` | The command can read a dedicated inherited file descriptor. Unix only. |
| `env` | The command requires a named environment variable. |

For a one-off command, bindings can be supplied on the command line:

```text
no-clone run production \
  --bind deploy-token=env:APP_TOKEN \
  --bind database-password=fd:3 \
  -- ./deploy.sh
```

## Passwords and profiles

The vault password is never stored. Each profile has its own expiration time,
and expired profiles are removed from the broker's active memory. Running
commands do not unlock profiles automatically.

Change the vault password with:

```text
no-clone change-password
```

The command verifies the current password and preserves the vault contents.

Profiles can be transferred between trusted installations as encrypted
bundles:

```text
no-clone profile export production --output production.no-clone
no-clone profile import production.no-clone --as production
```

## Rendering and security

Direct process delivery is the preferred workflow. Rendering is available for
applications that require a configuration file:

```text
no-clone profile render production --format dotenv --output .env
no-clone profile render production --format json --output secrets.json
no-clone profile render production --format yaml --stdout
```

Rendering and single-secret printing require a fresh vault-password prompt:

```text
no-clone secret print production database-password
```

Rendered files contain plaintext credentials and should be protected and kept
out of version control.

The broker uses protected per-user local IPC. Environment variables are set
only for the target process tree. After a credential has been delivered,
`no-clone` cannot stop the target from logging, copying, or disclosing it, and
it does not redact target stdout or stderr.

## Development

Run the test suite with:

```text
cargo test
```

The repository also contains the integration guide used by compatible command
automation tools at [skills/no-clone/SKILL.md](skills/no-clone/SKILL.md).

## License

MIT. See [LICENSE](LICENSE).
