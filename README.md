# okc-agents

SSH agent and GPG command adapters for [OpenKeychain](https://www.openkeychain.org/). Private-key operations run in OpenKeychain through the [OkcAgent companion fork](https://github.com/reo101/OkcAgent).

CLI 0.4.0 requires companion 0.3.0 for GPG protocol 2. The upstream 0.2.3 APK uses protocol 1 and is rejected. SSH retains protocol 0. Publish the companion first, then the CLI, then update downstream input locks. Install the matched pair together.

## Build and test

```sh
nix build
nix flake check
```

For local development:

```sh
nix develop
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --bins
python3 tests/test-gpg-cli.py target/debug/okc-gpg target/debug/okc-ssh-agent
```

The Nix checks include the Rust tests and the callback integration test. They exercise real TCP/Unix sockets with a fake Android broadcast command. They do not perform OpenKeychain cryptography.

The Nix package is a Linux binary for `nix-enter` or NoD, not an Android/Bionic binary. Native Termux builds are a separate target.

## SSH

Open the companion, select an SSH authentication subkey, and allow its notifications. To start the agent in a supervised session:

```sh
AM=/system/bin/am okc-ssh-agent start --foreground --addr "$HOME/.okc/ssh-agent.sock"
```

Point SSH clients at that socket through `SSH_AUTH_SOCK`. Create the parent directory first if you run the CLI directly. NNS supplies the supervised wrapper and directory preparation.

Hardware-backed keys require the token. A successful `ssh-add -L` does not prove that a signature or login completed.

## GPG subset

Supported actions are detached/cleartext signing, encryption, sign-plus-encrypt, decryption, verification, public export, SSH export, permission checks, metadata, and OpenKeychain encrypted backup.

```sh
okc-gpg --armor --export 0123456789ABCDEF > public-key.asc
okc-gpg --detach-sign --armor --local-user user@example.com < message > signature.asc
okc-gpg --encrypt -r first@example.com --encrypt-to 0123456789ABCDEF < message > message.gpg
okc-gpg --check-permission
```

Use real key IDs or email addresses in place of these examples. No signing-key selector falls back to another key after a provider failure.

`--backup --backup-secret` creates an encrypted OpenKeychain backup. It is not `gpg --export-secret-keys`. OpenKeychain controls authorization and the recovery code.

Key listings, colon records, fingerprints, secret-key export, key administration, keyservers, hidden recipients, batch mode, passphrase injection, and signed-packet `--sign` without encryption fail explicitly. Perform key management in OpenKeychain. No listing command triggers backup.

The CLI keeps diagnostics and `am broadcast` output out of stdout. `--status-fd 2` emits a minimal signing-success marker, not the complete GnuPG status protocol. Do not shadow `gpg` globally.

See [docs/okc-api.md](docs/okc-api.md) for the public API matrix and the exact limits.

## NNS integration

The [NNS module](https://github.com/reo101/NNS/blob/master/nix/nns-system/okc-agents.nix) runs a root longrun with a socket in the consumer's home. Its dedicated socket directory is root-owned. The consumer home restricts access. Android application domains generally need separate sockets.

The module exports `SSH_AUTH_SOCK` through an NNS profile. Its NoD module exposes `nns.sshAgentSocket` for the login environment. The profile also provides explicit `okc-gpg` with `AM=/system/bin/am`.

Use a published GitHub input in downstream flakes:

```nix
okc-agents.url = "github:reo101/okc-agents";
```

After publishing this repository, update the downstream input lock. Do not commit machine-local path inputs or lock to an unpublished revision.

## Device verification

A complete device test requires the matching companion and manual OpenKeychain interaction. Run public export, sign/verify, encrypt/decrypt, cancellation during authorization, and SSH login separately. Do not automate key administration or permission approval on a personal device.

Earlier cheetah testing reached SSH public-key acceptance and the OpenKeychain prompt. No completed hardware-token login is claimed. The corrected transport and lifecycle have host regression coverage. A new APK build is not evidence of a device cryptographic round-trip.
