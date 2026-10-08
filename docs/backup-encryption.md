# Local backup encryption

The `ibackup` Rust crate reads completed Finder/iTunes backups with `Manifest.db`.
It does not modify backups or export decrypted files. iSafety calls it through
the C ABI in `macos/Sources/CIsafety/include/isafety.h`.

## Research and implementation

Apple describes password-protected backup keybags and the modern 10-million-round
PBKDF2 work factor in [Keybags for Data Protection](https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web).
The byte-level format is not a stable public Apple API. Format references consulted:

- [Keybags and archived file metadata](https://github.com/jsharkey13/iphone_backup_decrypt/blob/master/src/iphone_backup_decrypt/utils.py)
- [Manifest/file decryption flow](https://github.com/jsharkey13/iphone_backup_decrypt/blob/master/src/iphone_backup_decrypt/iphone_backup.py)
- [iOS backup format notes](https://github.com/pmeenan/golemine/blob/main/docs/iOS-Backup-Format.md)
- [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), including its AES-256 key-wrap test vector
- [Backup reader input-validation advisory](https://github.com/jsharkey13/iphone_backup_decrypt/security/advisories/GHSA-63p2-3674-32xw)

No reference implementation is bundled or executed at runtime. Cryptographic
primitives come from RustCrypto crates; format parsing and orchestration are Rust.

1. Parse `Manifest.plist` and its `IsEncrypted` flag.
2. Parse `BackupKeyBag` as length-checked TLV records: four-byte tag, big-endian
   length. UUID boundaries separate the header from per-class records.
3. Modern bags: PBKDF2-HMAC-SHA256 using `DPSL`/`DPIC`, followed by
   PBKDF2-HMAC-SHA1 using `SALT`/`ITER`, each producing 32 bytes. Bags with neither
   modern field use only the SHA1 stage. A partial modern pair is an error.
4. RFC 3394 unwrap of password-wrapped AES class keys. A failed unwrap reports
   “incorrect password or damaged keybag”; these cannot reliably be distinguished.
5. Read the little-endian class and wrapped key in `ManifestKey`. Unwrap it,
   decrypt `Manifest.db` with AES-256-CBC and a zero IV, then validate PKCS#7
   padding and SQLite structure.
6. Deserialize SQLite into a read-only in-memory connection. For selected files,
   resolve the NSKeyedArchiver root, `EncryptionKey` UID/`NS.data`, `ProtectionClass`,
   and `Size`; unwrap the file key and decrypt the payload. Validate padding and size.

## Supported scope and limits

- Modern encrypted local backups and the earlier single-stage KDF in a
  **Manifest.db-based** backup. XML/binary plists; sharded/flat file storage.
- Empty and UTF-8 passwords. The C interface accepts arbitrary password bytes,
  including embedded NULs. A null pointer means no password was supplied.
- Device-bound/asymmetric classes, iCloud backups, `Manifest.mbdb`, backup creation,
  writing/re-encryption, and keychain decryption are not implemented.
- Maximum manifest: 512 MiB; selected file/plist: 32 MiB; per-file metadata: 1 MiB;
  keybag: 64 KiB; entries: 2 million; findings: 10,000; warnings: 1,000.
- KDF limits: DPIC 1–20 million, ITER 1–1 million. These bound work on untrusted
  input. They are not recommended encryption settings.
- CBC does not authenticate all file contents. Padding, size and SQLite checks
  cannot prove absence of tampering. Size mismatches produce artifact read errors,
  including for legitimate but inconsistent backups.
- The app stays responsive but cannot yet cancel a running KDF.
- Tested with independent synthetic fixtures; real-device/version compatibility
  is **not yet established**. Do not claim support for every iOS release.

## Data handling

Open files read-only through directory-relative, no-follow descriptors. Never use
manifest-relative paths as extraction destinations. Require 40-hex-character file
IDs. Reject SQLite journals instead of silently ignoring unfinished transactions.
Use completed stable snapshots; the reader does not lock backups against changes.

No decrypted temporary database or extracted file is written to disk. Rust-owned
password copies, derived/class/file keys, and payload buffers are zeroized on drop.
This does **not** guarantee protection against swap, crash dumps, SQLite/plist
internal allocations, or Swift String/SecureField copies. SQLite memory is released
normally, not guaranteed wiped. Reports contain sensitive device/artifact data and
are saved only through the explicit export action.

## Relationship to libibackup

Inspected the local [hack-different/libibackup](https://github.com/hack-different/libibackup)
checkout at `b684b358affc347ba6a9b9c5b3ee9fd9fd19be4a`. Its C reader has a useful
domain/file model, but opens SQLite read-write, has unchecked I/O and ownership
defects, and does not implement encrypted backups. This project implements a new
read-only reader instead of linking that library or adding a submodule.

The `ibackup` crate is isolated for possible extraction into that project later.
The iSafety C ABI is a new scan/report API, **not ABI-compatible** with
`libibackup_client_t`. A lower-level C handle API for arbitrary backup file access
remains a future extension.

## Verification

`scripts/generate-fixtures.py` uses hashlib/plistlib/sqlite3 and cryptography's
OpenSSL backend, independently of Rust, to create committed synthetic fixtures.
Password: `fixture-password-🔐`; one fixture uses an empty password. Reduced KDF
counts keep tests fast. Python is only needed to regenerate fixtures.

Tests compare decrypted files byte-for-byte with a plain backup, cover both KDFs,
the RFC vector, missing/wrong passwords, truncation, iteration limits, unsafe IDs,
symlinks, missing artifacts, source preservation, C ABI calls and Swift decoding.
