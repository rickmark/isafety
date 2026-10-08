# iSafety

A native macOS app for reviewing security-relevant artifacts in iPhone and iPad
backups. SwiftUI presents the results; a Rust engine reads and decrypts backups
through a C API. Analysis runs locally and leaves the backup unchanged.

This is an early working implementation, not a comprehensive compromise detector.
Findings identify artifacts to review; their presence does not establish a threat,
and an empty report does not establish that a device is safe.

## Build and run

Requires macOS 14+, Xcode/Swift 6+, and Rust 1.94+. No Python runtime, Homebrew
libraries, or external service is required by the app.

```sh
./scripts/build-macos.sh
open build/iSafety.app
```

Choose a completed backup containing `Info.plist`, `Manifest.plist`, and
`Manifest.db`. Encrypted backups prompt for the backup password. Review findings,
coverage, and warnings, then optionally export JSON.

The script builds for the host architecture and ad-hoc signs a sandboxed `.app`.
For local signing with an installed identity, set `ISAFETY_SIGNING_IDENTITY`.
Store distribution still needs an Apple team/bundle identity, provisioning,
distribution signing, release assets, and App Store validation. This is not a
submission-ready archive. Open `macos/Package.swift` in Xcode after building the
Rust release library; use the bundled app to exercise sandbox behavior.

## Layout

| Location | Purpose |
| --- | --- |
| `crates/ibackup` | Read-only access, keybags, manifest and file decryption |
| `crates/isafety-core` | Scanning rules, versioned JSON reports, exported C functions |
| `macos` | SwiftUI app, C header, sandbox entitlements, bundle metadata |
| `legacy/python` | Original source, tests, metadata and lockfile, including existing unfinished changes |
| `docs/backup-encryption.md` | Research, limits, libibackup assessment |

The existing GPL license remains in place. No relicensing or dependency on the C
libibackup implementation has been introduced.

## Current checks

Configuration profiles, pairing records, Bluetooth records, and disabled services
are parsed. Managed preferences, carrier settings, provisioning profiles, and
Watch backup artifacts are inventoried. SMS, TCC, live-device collection,
sysdiagnose and IPSW analysis are not implemented in the native app.

Encrypted backup support has synthetic fixtures for modern and legacy derivation.
Real-device validation is still needed. See [encryption details](docs/backup-encryption.md).

## Test

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/build-macos.sh
swift test --package-path macos
```

The C header documents buffer ownership and passwords. Calls block and must run
off the UI thread. Errors have a JSON envelope with stable codes. Independent
scans can run concurrently; there is no global backup context.

The original README and dedication are preserved in `legacy/python/README.md`.
