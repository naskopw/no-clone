---
name: no-clone
description: Safely use the no-clone local secret broker from an AI agent. Use when a repository contains .no-clone.yaml, a task needs credentials through no-clone run, bindings or transports must be added, a profile is locked, or an agent needs to explain the no-clone workflow without handling secret values.
---

# No-Clone Agent Workflow

Use no-clone to request secret delivery by name while keeping secret values out of the agent workflow. Treat the user as the only party authorized to unlock the vault and perform plaintext export.

## Core rules

- Never ask the user to paste a secret value into chat, a prompt, an argument, an environment variable, or a generated file.
- Never read, guess, log, echo, or transform a secret value.
- Never run **no-clone unlock**; unlocking requires the user's vault password and an interactive user action.
- Never run **no-clone profile render** or **no-clone secret print**; both intentionally create plaintext exposure and require the user to authenticate again.
- Never use **env**, **printenv**, shell tracing, debug dumps, or equivalent commands when they could print delivered secrets.
- Use profile names, secret names, transport names, and target variable names only.
- A fingerprint token is shareable metadata, not a secret value. Agents may
  run **no-clone secret verify** with a user-provided fingerprint token, but
  must not attempt to derive, guess, or transform secret values.
- Remember that no-clone does not redact target stdout or stderr. If the target prints a secret, it can appear in the command result. Do not intentionally invoke commands that print delivered credentials, and do not repeat sensitive output in later messages.

The repository manifest is configuration, not authorization. It may declare multiple profiles and bindings nested under each profile. Do not add hashes, signatures, approval workflows, or automatic unlock behavior.

## Normal workflow

1. Look for **.no-clone.yaml** in the repository.
2. Read it for the profiles, secret names, and transports required by the target command.
3. Run the target through the broker:

   ~~~text
   no-clone run --manifest .no-clone.yaml -- ./deploy.sh
   ~~~

4. If the broker reports that a profile is locked or expired, stop and tell the user which profile names must be unlocked. Do not retry with a password or attempt to unlock automatically.
5. Preserve the target's exit status and report ordinary command output without exposing or repeating credential material.

The user should unlock profiles separately, for example:

~~~text
no-clone unlock production registry
~~~

For a profile requiring user authorization before every delivery, the user can choose zero-trust mode:

~~~text
no-clone unlock production --zero-trust
~~~

If a zero-trust run asks for a vault password, stop and tell the user to inspect and authorize the command. Never provide, guess, relay, or request the password on the user's behalf.

Unlocks expire independently. A running target keeps responsibility for any value it has already received; locking later does not revoke that delivered value.

## Manifest bindings

Use this schema for repository configuration:

~~~yaml
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
~~~

Declare secret names and delivery instructions only. Never put values in the manifest. If a needed binding is absent and the secret name is known, add the binding without requesting or inventing its value. If the secret name is unknown, ask the user for the name, not the value.

Prefer transports in this order when the target supports them:

1. **fd:NUMBER** for a dedicated inherited descriptor on Unix.
2. **stdin** when the target consumes its standard input as the credential.
3. **env:NAME** when the target requires a named environment variable or the other transports are unavailable.

Use environment bindings only for the target process. Do not export them into the agent shell or copy them into a .env file.

## One-off bindings

When a repository manifest is not appropriate, use direct bindings with the profile name:

~~~text
no-clone run production \
  --bind deploy-token=env:APP_TOKEN \
  --bind tls-cert=fd:3 \
  -- ./deploy.sh
~~~

Supported forms are:

~~~text
SECRET=stdin
SECRET=env:VARIABLE_NAME
SECRET=fd:3
~~~

Keep all secret values out of the command line. The command after **--** is the target that receives the selected values.

## User-only operations

Leave these operations to the user unless the user explicitly changes the operating policy:

- **no-clone init**
- **no-clone profile create**, **delete**, **render**, **export**, or **import**
- **no-clone secret set**, **delete**, or **print**
- **no-clone secret fingerprint** and **no-clone fingerprint rotate-key**
- **no-clone change-password**
- **no-clone unlock**
- **no-clone unlock PROFILE --zero-trust** when the user has not explicitly requested that session policy
- **no-clone lock** when it would change the user's active sessions unexpectedly

It is safe to suggest the user run **no-clone status** to inspect active profiles. It is also safe to suggest **no-clone lock PROFILE** after the task when the user wants the profile locked.

To verify a user-provided fingerprint, use the named profile and secret only:

~~~text
no-clone secret verify production deploy-token \
  --fingerprint nc-fp-v1.<key-id>.<tag>
~~~

Verification requires the profile to be unlocked, returns only a status, and
does not deliver the secret. It is safe to run autonomously for zero-trust
profiles because it does not disclose a credential.

Do not use repository manifests for plaintext rendering or profile export. Rendering is a separate, explicit user-authorized escape hatch.

## Failure handling

- **profile is locked or expired**: report the exact profile names and ask the user to unlock them.
- **secret does not exist**: verify the manifest secret name against the task configuration; ask the user for the correct name if necessary. Do not inspect the vault yourself.
- **stdin binding** conflicts with the target's normal input: prefer an FD or environment binding if the target supports it.
- **fd transport** is unavailable on the current platform: use stdin or environment delivery when appropriate.
- target output contains a credential: stop repeating it, warn that the target disclosed its input, and let the user decide how to handle the target.
