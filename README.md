# no-clone

`no-clone` is like a password manager for AI agents. You keep API keys,
deployment tokens, and passwords in an encrypted vault on your machine. When an
agent needs a credential, it asks for it by name, and `no-clone` delivers it
directly to the command that needs it. The value does not have to appear in
chat, the agent's context, command arguments, shell history, or the repository.

> ⚠️ **Not a sandbox:** The launched command receives the credential and can
> still log, copy, or disclose it. `no-clone` does not redact target output or
> protect against a malicious target command.

> ⚠️ **Early-stage software:** `no-clone` has not had a full independent
> security audit. Evaluate it carefully before using it with production
> credentials.

## Main concepts

| Concept | What it means |
| --- | --- |
| **Vault** | The encrypted SQLCipher database stored on the human's machine. Its password is never stored. |
| **Profile** | A named group of related secrets, such as `production` or `registry`, with its own unlock lifetime. |
| **Secret** | An opaque value addressed by a non-sensitive name such as `deploy-token`. |
| **Manifest** | A repository-safe `.no-clone.yaml` file listing the profiles, secret names, and delivery methods a command needs. It never contains values. |
| **Binding** | The route from one named secret to the target process: a file descriptor, standard input, or an environment variable. |
| **Broker** | The per-user local background process that holds unlocked profiles in memory and launches target commands. |
| **Agent skill** | The bundled instructions that teach a compatible agent how to use `no-clone` without handling secret values. |
| **Fingerprint** | Optional shareable metadata that lets an agent verify a secret against an expected value without retrieving either value. |

A manifest is configuration, not authorization. Committing one tells an agent
how to request credentials, but the corresponding profiles must exist in the
human's local vault and must be explicitly unlocked before use.

## 🤖 Included agent skill

The CLI handles secret storage and delivery. The repository also ships the
agent-side integration as a ready-to-use skill in
[`skills/no-clone/`](skills/no-clone/). Its
[`SKILL.md`](skills/no-clone/SKILL.md) teaches a compatible coding agent to:

- find and read the repository's `.no-clone.yaml` manifest;
- request credentials by profile and secret name only;
- run commands through `no-clone run`;
- leave unlocking and plaintext operations to the human;
- avoid commands that could print delivered credentials; and
- handle locked, expired, or missing profiles without asking for secret values.

Install or load the `skills/no-clone/` directory through your agent's normal
skill mechanism. With agents that support named skills, invoke it directly:

```text
Use $no-clone to run ./deploy.sh with the repository secret bindings.
```

## 🚀 Quick start

### 1. Install

Install from a local checkout with Cargo:

```text
cargo install --path .
```

This installs the `no-clone` executable in Cargo's binary directory.

### 2. Human: create the vault and add credentials

```text
no-clone init
no-clone profile create production
no-clone secret set production deploy-token --prompt
```

`init` creates the encrypted local vault. `secret set --prompt` reads the value
from a hidden prompt, so it does not enter shell history. A profile's default
unlock lifetime is 1,800 seconds; set a different value with `--ttl SECONDS`
when creating it.

Exact arbitrary bytes can be imported from a human-owned file instead:

```text
no-clone secret set production signing-key --from-file /trusted/path/signing.key
```

Do not ask an agent to read that file or paste its contents into chat.

### 3. Project: declare what the command needs

Create `.no-clone.yaml` in the repository:

```yaml
version: 1

profiles:
  production:
    secrets:
      deploy-token:
        transport: env
        target: APP_TOKEN
```

This says: deliver the local secret named `production/deploy-token` to the
target process as `APP_TOKEN`. It does not contain the token.

### 4. Human: unlock the profile

```text
no-clone unlock production
```

Unlocking starts the broker when needed, asks for the vault password, and loads
the selected profile into broker memory until its TTL expires.

### 5. Agent: use the included skill to run the command

Load [`skills/no-clone/`](skills/no-clone/) in a compatible agent and ask it to
use `$no-clone`. The skill directs the agent to inspect the manifest and run the
target through the broker:

```text
no-clone run --manifest .no-clone.yaml -- ./deploy.sh
```

The agent supplies the manifest and command. The broker resolves the declared
names, starts `./deploy.sh`, and delivers `APP_TOKEN` only to that target process
tree. The target's exit status, standard output, and standard error are returned
normally.

When the profile is locked or expired, the command fails without unlocking it.
The agent should report the profile name and wait for the human to run
`no-clone unlock`.

### 6. Human: lock the profile when finished

```text
no-clone lock production
```

Running targets remain responsible for values already delivered to them;
locking a profile cannot revoke a credential from an existing process.

## 👥 Human and agent responsibilities

The intended division is simple: humans handle secret values and authorization;
agents handle names, bindings, and commands.

| Human | Agent |
| --- | --- |
| Initialize the vault and manage its password. | Read the manifest and refer to secrets only by profile/name. |
| Create, delete, import, and export profiles. | Add or update bindings when the required secret name is known. |
| Set, replace, and delete secret values. | Run targets through `no-clone run`. |
| Choose standard or zero-trust unlocks. | Report locked or missing profiles instead of attempting to unlock them. |
| Perform plaintext `print` or `render` operations. | Verify a user-provided fingerprint token when an identity check is needed. |
| Lock profiles and decide how long they stay unlocked. | Avoid commands that print delivered credentials or dump the target environment. |

In particular, an agent should never ask the human to paste a secret into a
prompt, argument, environment variable, generated file, or chat message. The
bundled agent skill encodes these rules so they do not depend on the agent
improvising the workflow correctly.

## Manifests and transports

A manifest can request multiple secrets from multiple profiles:

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
        transport: stdin
```

Choose the narrowest transport the target supports:

| Transport | Manifest form | Use when |
| --- | --- | --- |
| `fd` | `transport: fd` plus `target: 3` | The target can read a dedicated inherited file descriptor. Preferred; Unix only. |
| `stdin` | `transport: stdin` | The target expects the credential on standard input. A run can have only one stdin binding. |
| `env` | `transport: env` plus `target: NAME` | The target requires a named environment variable. The value must be UTF-8. |

Environment bindings are scoped to the target process tree. `no-clone` does
not export them into the agent's shell or write them to a `.env` file.

For a one-off command that does not need a repository manifest, use direct
bindings:

```text
no-clone run production \
  --bind deploy-token=env:APP_TOKEN \
  --bind signing-key=fd:3 \
  -- ./deploy.sh
```

The supported forms are `SECRET=stdin`, `SECRET=env:VARIABLE_NAME`, and
`SECRET=fd:NUMBER`. Values never belong in `--bind`.

## Unlock modes

### Standard

```text
no-clone unlock production
```

The broker may deliver that profile's secrets to matching requests until the
profile's TTL expires or the human locks it. Override the TTL for one session
with `--ttl SECONDS`.

### Zero trust

```text
no-clone unlock production --zero-trust
```

The profile is still loaded for a bounded session, but every command that would
receive one of its secrets requires the vault password again. `no-clone` shows
the requested profiles and command before prompting, giving the human a fresh
authorization point for each delivery.

An agent must stop at that prompt and let the human inspect and authorize the
command. Fingerprint verification does not deliver a credential, so it does not
trigger a zero-trust authorization prompt.

Inspect active sessions without revealing secret values:

```text
no-clone status
no-clone profile list
no-clone secret list production
```

## Verify a secret without revealing it

Sometimes the question is not “what is the value?” but “is the stored value the
one I expect?” A human can create a vault-keyed fingerprint from an expected
value obtained through an independent trusted channel:

```text
no-clone secret fingerprint production deploy-token --prompt
```

The command prints a token shaped like `nc-fp-v1.<key-id>.<tag>`. The token is
shareable metadata, not a credential. An agent can verify it against the stored
secret by name:

```text
no-clone secret verify production deploy-token \
  --fingerprint nc-fp-v1.<key-id>.<tag>
```

Verification returns `match`, `mismatch`, `stale`, or `missing` and never
delivers the secret. Fingerprints are bound to the vault, profile, secret name,
and exact expected bytes. They do not expire, but rotating the vault fingerprint
key permanently makes all existing tokens stale:

```text
no-clone fingerprint rotate-key
```

Fingerprint creation and key rotation are human-only operations because they
require trusted input or change verification state.

## Plaintext escape hatches and profile transfer

Direct process delivery is the preferred workflow. For applications that can
only read configuration files, a human can explicitly render a profile:

```text
no-clone profile render production --format dotenv --output .env
no-clone profile render production --format json --output secrets.json
no-clone profile render production --format yaml --stdout
```

A human can also print one secret:

```text
no-clone secret print production database-password
```

These operations require a fresh vault-password prompt. Their output is
plaintext: protect it, keep it out of version control, and do not perform it in
an agent-controlled session.

Profiles can be moved between trusted installations as password-protected,
encrypted bundles:

```text
no-clone profile export production --output production.no-clone
no-clone profile import production.no-clone --as production
```

Change the vault master password without replacing its contents:

```text
no-clone change-password
```

## 🛡️ Security boundaries

`no-clone` is designed to prevent accidental credential exposure in the
agent/request path:

- secret values are encrypted at rest in a local SQLCipher vault;
- unlocked profiles live in the per-user broker's memory for a bounded time;
- repository manifests and CLI bindings contain names and delivery instructions
  only;
- the local broker accepts clients from the current OS user on Unix; and
- credentials are attached only while launching the requested target process.

It deliberately does **not** guarantee that:

- a target process will keep the delivered credential confidential;
- target stdout or stderr is free of credentials;
- locking can revoke a value already delivered to a running process;
- another process with sufficient access to the same account or machine cannot
  inspect or interfere with local processes; or
- a malicious agent allowed to choose arbitrary commands cannot request a
  command that exfiltrates a delivered credential.

Use zero-trust mode when a human should inspect every credential-bearing
command, and only authorize targets you trust.

## Development

The project uses the Rust toolchain and Cargo. Build the CLI or run it directly
from the checkout:

```text
cargo build
cargo run -- --help
```

Before submitting a change, run the test, formatting, and lint checks:

```text
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## License

MIT. See [`LICENSE`](LICENSE).
