# OpenKeychain API coverage

`okc-agents` adapts SSH agent messages and a GPG command subset to the OkcAgent Android companion. OpenKeychain retains the private keys. The GPG client is not a GnuPG agent.

## Sources

The companion fork includes these public API sources under `libraries/`:

- `open-keychain/openpgp-api` at `f91db6be300e8a777c49bbcb8ad0b3a9a583ef08`.
- `open-keychain/open-keychain` SSH API at `8d0bd1f8537fb3a795fda8161f730a313ef7b01c`.

Provider behavior was compared with OpenKeychain's `remote/OpenPgpService.java` and `remote/SshAuthenticationService.java`. Current adapter behavior is defined by the companion's `GpgArguments.kt` and `GpgAgentService.kt`, and this repository's `src/bin/okc-gpg.rs`.

## OpenPGP API

| Public action | Current adapter |
| --- | --- |
| `CHECK_PERMISSION` | `--check-permission` |
| `SIGN` | Not used. Deprecated alias for cleartext signing, not GnuPG signed-packet output. |
| `CLEARTEXT_SIGN` | `--clear-sign`, `--clearsign` |
| `DETACHED_SIGN` | `--detach-sign`, `-b` |
| `ENCRYPT` | `--encrypt`, `-e` |
| `SIGN_AND_ENCRYPT` | `--sign --encrypt` |
| `DECRYPT_VERIFY` | `--decrypt`, `--verify`, or both |
| `DECRYPT_METADATA` | `--decrypt --metadata` |
| `GET_SIGN_KEY_ID` | Per-invocation signing-key resolution and companion key selection |
| `GET_SIGN_KEY_ID_LEGACY` | No direct CLI action |
| `GET_KEY_IDS` | Resolve recipient and public-export email selectors |
| `GET_KEY` | `--export` |
| `BACKUP` | `--backup`, with optional `--backup-secret` |
| `QUERY_AUTOCRYPT_STATUS` | Not exposed |
| `AUTOCRYPT_KEY_TRANSFER` | Not exposed |
| `UPDATE_AUTOCRYPT_PEER` | Not exposed |

There is no public import, generation, deletion, editing, revocation, or trust-database API. OpenKeychain's internal provider is not a stable public interface.

`GET_KEY_IDS` resolves supplied user IDs or starts a selection flow. It is not a complete key inventory API. It does not report secret-key availability or GnuPG keygrips. Implementing reliable GnuPG listings requires additional metadata and packet parsing.

`GET_KEY` returns public OpenPGP key packets. `--armor` requests ASCII armor. Full 16-digit key IDs and email addresses are supported selectors. With no selector, export uses the companion's configured GPG key. Invalid selectors do not silently export every key.

`BACKUP` writes an encrypted OpenKeychain backup and requires user interaction. OpenKeychain controls the recovery code. This is not equivalent to `gpg --export-secret-keys`, so that option is rejected. Public and secret key-listing commands never invoke backup.

## SSH API

| Public action | Current adapter |
| --- | --- |
| `SIGN` | SSH agent signature requests |
| `SELECT_KEY` | Companion SSH key selection |
| `GET_PUBLIC_KEY` | Not exposed |
| `GET_SSH_PUBLIC_KEY` | SSH identities and `--export-ssh-key` |

SSH export accepts a full 16-digit authentication subkey ID. The API identifies that subkey, not a GnuPG user-ID search. With no argument, the adapter tries the configured GPG key ID. This can fail if it names a primary key instead of an authentication subkey.

The SSH agent implements identity queries and signature requests. It does not implement identity import, key generation, smartcard administration, or a passphrase cache.

## Options and limits

Signing selectors:

- `--local-user` / `-u`.
- `--default-key`, with CLI alias `--default-user`.
- The companion's configured key when no selector is supplied.

A provider error or canceled selection fails the operation. It does not sign with a fallback key.

Encryption accepts repeated `--recipient` / `-r` and `--encrypt-to`. Email selectors resolve to key IDs before encryption. The adapter sends one combined key-ID array, so mixed numeric and email recipients do not replace each other.

Other supported options include armor, output path, original filename, compression on/off through a 0-9 compression level, and `--status-fd 2`. The compression level does not select a precise compression algorithm or ratio.

The adapter accepts harmless compatibility flags such as `--use-agent`, `--no-batch`, and warning/verbosity flags. `--yes` and `--no` do not approve OpenKeychain authorization. OpenKeychain owns that interaction.

The following requests fail explicitly:

- Key listings, colon records, fingerprints, keygrips, and secret-material availability.
- GnuPG secret-key export.
- Import, generation, deletion, editing, and keyserver operations.
- Signed-packet `--sign` without encryption. Cleartext and detached signing remain available.
- Hidden recipients and key-ID suppression.
- Batch mode, passphrase injection, command descriptors, and pinentry mode selection.
- Symmetric encryption, packet inspection, and smartcard administration.
- Alternate home directories, configuration files, keyrings, and trust databases.
- Trust overrides, packet-format overrides, and unsupported status descriptors.

The public API has an `EXTRA_PASSPHRASE` facility, but the CLI does not send passphrases in broadcast extras. A future implementation needs a separate private data channel and an explicit security review.

Metadata output is diagnostic text from `OpenPgpMetadata`. It is not a stable JSON schema or GnuPG listing. `--list-config` reports the companion version and provider, not GnuPG's algorithm inventory.

Only a minimal `[GNUPG:] SIG_CREATED` marker is emitted after successful signing. OpenPgpApi does not return all GnuPG status fields. Full GnuPG status compatibility is not claimed.

## Transport and cancellation

The CLI binds a loopback listener and broadcasts its port and base64-encoded arguments. The companion opens a control connection first. Input and output connections are lazy and can occur more than once. Actions that need no data streams complete on control alone.

The CLI processes connections concurrently. Callback paths must match the invocation's selected inputs and output. A callback cannot select an unrelated file for the CLI to read or overwrite. Transfer failures stop the invocation. On completion, it cancels input readers and drains successful output. An open stdin does not prevent process exit when the provider stops reading early. Diagnostics and `am broadcast` output do not enter stdout. Status messages requested on descriptor 2 are emitted without log prefixes.

The companion stages provider output until an attempt succeeds. Failed attempts and authorization retries do not duplicate partial output. Input replay supports binary bytes, incomplete first reads, and multiple authorization attempts.

Client disconnection interrupts authorization waits. SSH preserves incoming messages in a bounded pipe while detecting EOF. UI waits have a two-minute limit. Pending requests release the provider lock while they wait, and notification cleanup runs after completion and cancellation.

This remains a local broadcast/loopback transport. It has no authenticated protocol handshake. It does not establish a security boundary against other applications on the device. OpenKeychain authorization and Android application isolation remain relevant. Do not expose the callback listener beyond loopback.

## What needs separate work

A complete GnuPG replacement needs packet metadata, colon listings, fingerprints, keygrips, more status records, and explicit batch/authorization behavior. Adding accepted flags without those implementations is not compatibility.

Import and key administration remain OpenKeychain UI operations. Several tempting internal activities are not exported. Launching those activities from this companion is not a supported key-management API.

A real `gpg-agent` requires Assuan commands such as `PKSIGN` and `PKDECRYPT`, keygrip mapping, and primitive-level private-key operations. OpenPgpApi supplies message-level operations instead. That requires a separate app-side agent or OpenKeychain changes.

## Verification boundaries

Host checks cover argument validation, binary frames, control-only completion, repeated input streams, output-only completion, transfer failure, stdout purity, and the status channel. The companion's JVM tests compile its real lifecycle and GPG service against Android/provider stubs. They cover cancellation, independent requests during authorization, key selectors, mixed recipients, output staging, metadata, SSH export binding, and command rejection.

An APK build is not an OpenKeychain cryptographic round-trip. Earlier cheetah testing returned an SSH key and reached `Server accepts key`, but token signing and login did not complete. GPG reached its control connection and authorization flow. The repaired sources require a separate interactive device test. No real token signature or backup recovery is claimed by the host tests.
