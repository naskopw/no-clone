# Secret Fingerprints

## Overview

Vault-keyed secret fingerprints let a user give an LLM a safe, opaque
identifier for an independently obtained expected secret. An agent can then
verify that an unlocked stored secret matches that expected value without
receiving either value or a brute-forceable unkeyed hash.

Fingerprints never expire. They are bound to one vault, profile name, secret
name, and exact expected bytes. They remain valid through vault password
changes and become stale after fingerprint-key rotation.

## Requirements

### Functional

- `no-clone secret fingerprint PROFILE SECRET --prompt` reads an expected text
  value from a hidden prompt, prompts for the vault password, and prints only a
  token to stdout.
- `no-clone secret fingerprint PROFILE SECRET --from-file PATH` reads exact
  expected bytes from a user-owned file and prints only a token to stdout.
- Fingerprint generation requires exactly one of `--prompt` or `--from-file`,
  matching the input contract of `no-clone secret set`.
- `no-clone secret verify PROFILE SECRET --fingerprint TOKEN` asks the broker
  for a match result without prompting for a password or exposing the secret.
- Verification works autonomously for standard and zero-trust profiles once
  the profile is unlocked.
- `no-clone fingerprint rotate-key` shows a warning, requires the user to type
  `rotate`, prompts for the vault password, and invalidates all existing
  fingerprints.
- Rotation has no non-interactive confirmation override.
- Fingerprints support arbitrary secret bytes and exact-byte matching.
- GUI support, direct human-only comparison, and repository manifest
  configuration are out of scope.

### Security and non-functional

- Each vault stores a random 256-bit fingerprint key and random 128-bit
  key-generation ID inside the encrypted SQLCipher database.
- The fingerprint key is not derived from the vault password, so password
  changes preserve fingerprints.
- Key material is zeroized when no active profiles remain and is never logged
  or included in debug output.
- Verification never offers an API to hash agent-supplied guesses or return a
  computed tag.
- Fingerprint tokens are shareable metadata, not credentials or service
  authentication material.

## User Experience and Behavior

Generate a token from an independently obtained expected value:

```text
no-clone secret fingerprint production deploy-token --prompt
```

For binary values or values whose trailing bytes matter, read the expected
value from a file:

```text
no-clone secret fingerprint production deploy-token \
  --from-file /trusted/path/to/expected-token
```

The command reads the expected value, prompts for the vault password, and
prints only:

```text
nc-fp-v1.<key-id>.<tag>
```

The user can place that token in an agent prompt. The agent verifies it after
the profile has been explicitly unlocked:

```text
no-clone secret verify production deploy-token \
  --fingerprint nc-fp-v1.<key-id>.<tag>
```

Verification prints exactly one status word for a domain result. It does not
deliver the secret, so it does not require an additional password even for a
zero-trust profile.

Rotation warns that all existing fingerprints will become invalid, requires
the literal confirmation `rotate`, then prompts for the vault password. A
cancelled or failed rotation leaves the old key intact.

## Technical Design

### Token format and computation

Tokens use unpadded Base64URL and the format:

```text
nc-fp-v1.<base64url-key-id>.<base64url-hmac-tag>
```

The tag is an HMAC-SHA-256 over a fixed v1 domain separator, the key-generation
ID, and unambiguous 64-bit length-prefixed values for the profile name, secret
name, and expected bytes. HMAC verification uses the cryptographic library’s
constant-time verification routine.

HMAC-SHA-256 is used instead of a raw SHA-512 digest because the vault-held
key prevents an exposed token from being used for offline guessing. Password
hashing guidance otherwise calls for salted, deliberately expensive schemes;
see [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) and [NIST SP
800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

### Vault

New vaults create a `vault_metadata` row containing the fingerprint key and
key-generation ID. Existing vault-file compatibility is not required.

`Vault::fingerprint_key` loads and validates the fixed-size metadata. Key
rotation replaces both values in a transaction. Profile exports never copy
the source vault key; imported secrets therefore require new fingerprints in
the destination vault.

### Broker

The broker protocol adds requests for fingerprint verification and key
rotation. The broker loads the fingerprint key when profiles are unlocked and
keeps it in session state while at least one profile is active. Expiring or
locking the final profile drops the key.

Rotation is performed under the broker state lock. After a successful response,
verification uses only the new key, and old tokens return `stale`.

### Result contract

| Exit code | Output | Meaning |
| ---: | --- | --- |
| 0 | `match` | Secret exists and matches. |
| 1 | `mismatch` | Secret exists but bytes differ. |
| 2 | stderr error | Operational error, including locked/expired profile or malformed token. |
| 3 | `stale` | Token belongs to another key generation. |
| 4 | `missing` | Unlocked profile exists but the named secret is absent. |

Result precedence is: validate input, require an unlocked profile, report a
missing secret, report a stale key-generation ID, then perform HMAC
verification.

## Edge Cases and Error Handling

- Any byte difference, including a trailing newline, produces `mismatch`.
- Profile and secret names are included in the HMAC, so the same value under a
  different name does not match.
- Malformed, unsupported, or incorrectly sized tokens are operational errors.
- A token from another vault is reported as stale because its key-generation
  ID is not recognized by the current vault.
- Rotating a key does not change secret values or lock profiles.
- A fingerprint can be created before the named secret exists; verification
  reports `missing` until the secret is stored.
- Re-setting a secret to the expected bytes makes the fingerprint match.
- Profile export/import does not preserve fingerprint compatibility.

## Testing

Tests cover deterministic fingerprints, arbitrary external bytes, exact-byte
behavior, profile/name binding, malformed tokens, all status results, locked
and expired profiles, zero-trust verification, password-change stability,
immediate rotation invalidation, cancellation/failure behavior, and
export/import key separation. Tests also ensure fingerprint generation
requires an explicit input source, is token-only, and that verification never
exposes secret material.

## Future Considerations

The following are intentionally deferred:

- Direct human-only comparison (`secret compare`), returning `match`,
  `different`, or `missing` without creating a token.
- GUI support.
- Fingerprint expiry.
- Non-interactive key rotation.
- Cross-vault fingerprints.
- Persistent fingerprint fields in `.no-clone.yaml`.
