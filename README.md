![Build status](https://github.com/DDoSolitary/okc-agents/workflows/.github/workflows/build.yml/badge.svg)

See https://github.com/DDoSolitary/OkcAgent for details of this project.

<https://github.com/nix-community/nix-on-droid/issues/371>

## Testing

### Local (host-only) checks

Run these first to validate CLI shape, argument validation, and protocol framing logic:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Android end-to-end checks

The `nix-on-droid` maintainers run Android automation via
[`droidctl`](https://github.com/t184256/droidctl), which wraps
`uiautomator2` and can target either an emulator or a real device over `adb`.
The workflow invocation reference is:

<https://github.com/nix-community/nix-on-droid/blob/40b8c7465f78887279a0a3c743094fa6ea671ab1/.github/workflows/emulator.yml#L189>

A practical loop for this repo is:

1. Build/install `okc-gpg` and `okc-ssh-agent` on a device with `OpenKeychain` and `OkcAgent`.
2. Run smoke commands manually (`okc-gpg --list-config`, `okc-ssh-agent --help`) to verify startup.
3. Run one signed/encrypt-decrypt path with `okc-gpg` and one `ssh-add -L`/SSH auth path through `okc-ssh-agent`.
4. Mirror those interactions in a `droidctl` script for repeatable CI-style automation.
