use ibackup::{Backup, Error};
use plist::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
fn password() -> &'static [u8] {
    "fixture-password-🔐".as_bytes()
}
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()));
        } else {
            fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

#[test]
fn decrypts_independently_generated_backups_byte_for_byte() {
    let plain = Backup::open(&fixture("plain"), None).unwrap();
    for name in [
        "encrypted-modern",
        "encrypted-legacy-kdf",
        "encrypted-empty-password",
    ] {
        let supplied = if name.ends_with("empty-password") {
            b"".as_slice()
        } else {
            password()
        };
        let encrypted = Backup::open(&fixture(name), Some(supplied)).unwrap();
        assert!(encrypted.info.encrypted);
        assert_eq!(encrypted.info.file_count, 4);
        assert!(encrypted.warnings.is_empty());
        encrypted
            .visit_entries(|entry| {
                assert_eq!(*encrypted.read_file(&entry)?, *plain.read_file(&entry)?);
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn password_required_and_wrong_password_are_distinct() {
    assert!(matches!(
        Backup::open(&fixture("encrypted-modern"), None),
        Err(Error::PasswordRequired)
    ));
    assert!(matches!(
        Backup::open(&fixture("encrypted-modern"), Some(b"wrong")),
        Err(Error::PasswordOrKeybag)
    ));
}

#[test]
fn scanning_leaves_original_bytes_unchanged() {
    let folder = tempfile::tempdir().unwrap();
    copy_tree(&fixture("encrypted-modern"), folder.path());
    let before = fs::read(folder.path().join("Manifest.db")).unwrap();
    let backup = Backup::open(folder.path(), Some(password())).unwrap();
    backup
        .visit_entries(|entry| {
            backup.read_file(&entry)?;
            Ok(())
        })
        .unwrap();
    drop(backup);
    assert_eq!(before, fs::read(folder.path().join("Manifest.db")).unwrap());
    assert_eq!(
        fs::read_dir(folder.path()).unwrap().count(),
        fs::read_dir(fixture("encrypted-modern")).unwrap().count()
    );
}

#[test]
fn rejects_excessive_kdf_work_and_truncated_keybags() {
    for truncate in [false, true] {
        let folder = tempfile::tempdir().unwrap();
        copy_tree(&fixture("encrypted-modern"), folder.path());
        let path = folder.path().join("Manifest.plist");
        let mut manifest = Value::from_file(&path).unwrap();
        let bag = manifest
            .as_dictionary_mut()
            .unwrap()
            .get_mut("BackupKeyBag")
            .unwrap()
            .as_data()
            .unwrap();
        let mut bag = bag.to_vec();
        if truncate {
            bag.truncate(bag.len() - 1);
        } else {
            let pos = bag.windows(4).position(|w| w == b"DPIC").unwrap();
            bag[pos + 8..pos + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        manifest
            .as_dictionary_mut()
            .unwrap()
            .insert("BackupKeyBag".into(), Value::Data(bag));
        manifest.to_file_binary(path).unwrap();
        let result = Backup::open(folder.path(), Some(password()));
        if truncate {
            assert!(matches!(result, Err(Error::Format(_))));
        } else {
            assert!(matches!(result, Err(Error::Limit(_))));
        }
    }
}

#[test]
fn rejects_symlinks_and_traversal_ids() {
    let folder = tempfile::tempdir().unwrap();
    copy_tree(&fixture("plain"), folder.path());
    let backup = Backup::open(folder.path(), None).unwrap();
    let mut entries = Vec::new();
    backup
        .visit_entries(|entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    let mut entry = entries.remove(0);
    let path = folder.path().join(&entry.file_id[..2]).join(&entry.file_id);
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(fixture("plain").join("Info.plist"), path).unwrap();
    assert!(backup.read_file(&entry).is_err());
    entry.file_id = "../outside".into();
    assert!(backup.read_file(&entry).is_err());
}

#[test]
fn rejects_corrupt_ciphertext_and_unfinished_sqlite_manifest() {
    let folder = tempfile::tempdir().unwrap();
    copy_tree(&fixture("encrypted-modern"), folder.path());
    let path = folder.path().join("Manifest.db");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop();
    fs::write(&path, bytes).unwrap();
    assert!(Backup::open(folder.path(), Some(password())).is_err());
    fs::write(folder.path().join("Manifest.db-wal"), []).unwrap();
    assert!(matches!(
        Backup::open(folder.path(), Some(password())),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn damaged_file_padding_is_not_returned_as_plaintext() {
    let folder = tempfile::tempdir().unwrap();
    copy_tree(&fixture("encrypted-modern"), folder.path());
    let backup = Backup::open(folder.path(), Some(password())).unwrap();
    backup
        .visit_entries(|entry| {
            let path = folder.path().join(&entry.file_id[..2]).join(&entry.file_id);
            let mut bytes = fs::read(&path).unwrap();
            // Flip the final plaintext byte via the previous CBC block, guaranteeing
            // a PKCS#7 value outside 1..16 rather than relying on random corruption.
            let position = bytes.len() - 17;
            bytes[position] ^= 0x80;
            fs::write(path, bytes).unwrap();
            assert!(matches!(backup.read_file(&entry), Err(Error::Crypto)));
            Ok(())
        })
        .unwrap();
}

#[test]
fn missing_modern_kdf_field_does_not_downgrade_to_legacy() {
    let folder = tempfile::tempdir().unwrap();
    copy_tree(&fixture("encrypted-modern"), folder.path());
    let path = folder.path().join("Manifest.plist");
    let mut manifest = Value::from_file(&path).unwrap();
    let mut bag = manifest.as_dictionary().unwrap()["BackupKeyBag"]
        .as_data()
        .unwrap()
        .to_vec();
    let pos = bag.windows(4).position(|tag| tag == b"DPIC").unwrap();
    bag.drain(pos..pos + 12);
    manifest
        .as_dictionary_mut()
        .unwrap()
        .insert("BackupKeyBag".into(), Value::Data(bag));
    manifest.to_file_binary(path).unwrap();
    assert!(matches!(
        Backup::open(folder.path(), Some(password())),
        Err(Error::Format(_))
    ));
}

#[test]
fn rejects_unavailable_manifest_protection_class() {
    let folder = tempfile::tempdir().unwrap();
    copy_tree(&fixture("encrypted-modern"), folder.path());
    let path = folder.path().join("Manifest.plist");
    let mut manifest = Value::from_file(&path).unwrap();
    let mut key = manifest.as_dictionary().unwrap()["ManifestKey"]
        .as_data()
        .unwrap()
        .to_vec();
    key[..4].copy_from_slice(&99u32.to_le_bytes());
    manifest
        .as_dictionary_mut()
        .unwrap()
        .insert("ManifestKey".into(), Value::Data(key));
    manifest.to_file_binary(path).unwrap();
    assert!(matches!(
        Backup::open(folder.path(), Some(password())),
        Err(Error::Unsupported(_))
    ));
}
