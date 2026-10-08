use isafety_core::{isafety_clear_bytes, isafety_scan_backup, isafety_string_free, scan};
use std::{
    ffi::{CStr, CString},
    path::Path,
};

#[test]
fn scans_encrypted_backup_through_c_abi() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ibackup/tests/fixtures/encrypted-modern");
    let path = CString::new(path.to_str().unwrap()).unwrap();
    let password = "fixture-password-🔐".as_bytes();
    unsafe {
        let pointer = isafety_scan_backup(path.as_ptr(), password.as_ptr(), password.len());
        let result: serde_json::Value =
            serde_json::from_slice(CStr::from_ptr(pointer).to_bytes()).unwrap();
        isafety_string_free(pointer);
        assert!(result.get("error").is_none(), "{result}");
        assert_eq!(result["findings"].as_array().unwrap().len(), 4);
        assert_eq!(result["coverage"].as_array().unwrap().len(), 8);
        assert_eq!(result["backup"]["encrypted"], true);
        assert!(!result.to_string().contains("fixture-password"));
    }
}

#[test]
fn ffi_handles_missing_and_invalid_arguments() {
    unsafe {
        let pointer = isafety_scan_backup(std::ptr::null(), std::ptr::null(), 0);
        assert!(CStr::from_ptr(pointer)
            .to_str()
            .unwrap()
            .contains("invalid_argument"));
        isafety_string_free(pointer);
        isafety_string_free(std::ptr::null_mut());
        let mut secret = [0x42u8; 32];
        isafety_clear_bytes(secret.as_mut_ptr(), secret.len());
        assert_eq!(secret, [0u8; 32]);
    }
}

#[test]
fn missing_evidence_is_reported_as_incomplete_coverage() {
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ibackup/tests/fixtures/plain");
    let folder = tempfile::tempdir().unwrap();
    for file in [
        "Info.plist",
        "Manifest.plist",
        "Manifest.db",
        "Status.plist",
    ] {
        std::fs::copy(original.join(file), folder.path().join(file)).unwrap();
    }
    let report = scan(folder.path(), None).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.warnings.len(), 4);
    assert_eq!(report.coverage.iter().map(|c| c.errors).sum::<u64>(), 4);
}

#[test]
fn inventories_watch_directories_and_original_provisioning_paths() {
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ibackup/tests/fixtures/plain");
    let folder = tempfile::tempdir().unwrap();
    for file in [
        "Info.plist",
        "Manifest.plist",
        "Manifest.db",
        "Status.plist",
    ] {
        std::fs::copy(original.join(file), folder.path().join(file)).unwrap();
    }
    let database = rusqlite::Connection::open(folder.path().join("Manifest.db")).unwrap();
    for (id, domain, path, flags) in [
        (
            "1".repeat(40),
            "HomeDomain",
            "Library/NanoBackup/00112233-4455-6677-8899-aabbccddeeff",
            2,
        ),
        (
            "2".repeat(40),
            "MobileDeviceDomain",
            "Library/ProvisioningProfiles/00112233-4455-6677-8899-aabbccddeeff",
            1,
        ),
        (
            "3".repeat(40),
            "HomeDomain",
            "Library/NanoBackup/not-a-watch-backup",
            2,
        ),
    ] {
        database
            .execute(
                "INSERT INTO Files VALUES (?1, ?2, ?3, ?4, NULL)",
                rusqlite::params![id, domain, path, flags],
            )
            .unwrap();
    }
    drop(database);
    let report = scan(folder.path(), None).unwrap();
    assert_eq!(report.findings.len(), 2);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "Watch backups"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "Provisioning profiles"));
}
