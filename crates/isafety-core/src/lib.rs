//! iSafety scanning engine and C interface.
use ibackup::{Backup, BackupInfo, Entry, Error};
use plist::Value;
use serde::Serialize;
use std::{
    ffi::{c_char, CStr, CString},
    io::Cursor,
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub title: String,
    pub explanation: String,
    pub domain: String,
    pub relative_path: String,
    pub file_id: String,
}

#[derive(Serialize)]
pub struct Coverage {
    pub category: String,
    pub matched: u64,
    pub inspected: u64,
    pub errors: u64,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub backup: BackupInfo,
    pub findings: Vec<Finding>,
    pub coverage: Vec<Coverage>,
    pub warnings: Vec<String>,
    pub scope: &'static str,
}

const CATEGORIES: [&str; 8] = [
    "Configuration profiles",
    "Managed preferences",
    "Pairing records",
    "Bluetooth devices",
    "Disabled services",
    "Carrier settings",
    "Provisioning profiles",
    "Watch backups",
];

fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn category(entry: &Entry) -> Option<usize> {
    let path = entry.relative_path.as_str();
    match entry.domain.as_str() {
        "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"
            if path.contains("profile-") =>
        {
            Some(0)
        }
        "ManagedPreferencesDomain" if path.ends_with(".plist") => Some(1),
        "HomeDomain" if path == "Library/Preferences/com.apple.mobile.ldpair.plist" => Some(2),
        "SysSharedContainerDomain-systemgroup.com.apple.bluetooth"
            if path == "Library/Preferences/com.apple.MobileBluetooth.devices.plist" =>
        {
            Some(3)
        }
        "DatabaseDomain" if path == "com.apple.xpc.launchd/disabled.plist" => Some(4),
        "HomeDomain"
            if path.starts_with("Library/Preferences/com.apple.carrier")
                || path.starts_with("Library/Preferences/com.apple.operator") =>
        {
            Some(5)
        }
        "MobileDeviceDomain"
            if path.ends_with(".mobileprovision")
                || path.ends_with(".provisionprofile")
                || path.split('/').any(is_uuid) =>
        {
            Some(6)
        }
        "HomeDomain"
            if path
                .strip_prefix("Library/NanoBackup/")
                .is_some_and(is_uuid) =>
        {
            Some(7)
        }
        _ => None,
    }
}

fn inspect(
    backup: &Backup,
    entry: &Entry,
    category: usize,
) -> ibackup::Result<Vec<(String, &'static str)>> {
    if matches!(category, 1 | 5 | 6 | 7) {
        return Ok(vec![(
            entry.relative_path.clone(),
            "Inventory entry from the backup manifest; contents and trust have not been evaluated.",
        )]);
    }
    let bytes = backup.read_file(entry)?;
    let value = Value::from_reader(Cursor::new(&*bytes))?;
    let values = value
        .as_dictionary()
        .ok_or(Error::Format("scanner expected a property-list dictionary"))?;
    let results = match category {
        0 => vec![(values.get("PayloadDisplayName").and_then(Value::as_string).unwrap_or("Configuration profile").to_string(), "A configuration profile can configure device settings. Review whether you recognize its source; presence alone does not establish a threat.")],
        2 => values.keys().map(|key| (key.clone(), "Pairing record identifier. Review whether you recognize the paired computer or service.")).collect(),
        3 => values.keys().map(|key| (key.clone(), "Bluetooth device recorded in the backup. A saved device is not evidence of current tracking.")).collect(),
        4 => values.iter().filter(|(_, value)| value.as_boolean() == Some(true)).map(|(key, _)| (key.clone(), "Service marked disabled in the backup. System configuration can legitimately disable services.")).collect(),
        _ => unreachable!(),
    };
    Ok(results)
}

pub fn scan(path: &Path, password: Option<&[u8]>) -> ibackup::Result<Report> {
    let backup = Backup::open(path, password)?;
    let mut findings = Vec::new();
    let mut warnings = backup.warnings.clone();
    let mut coverage: Vec<_> = CATEGORIES
        .iter()
        .map(|category| Coverage {
            category: category.to_string(),
            matched: 0,
            inspected: 0,
            errors: 0,
        })
        .collect();
    backup.visit_entries(|entry| {
        let Some(index) = category(&entry) else {
            return Ok(());
        };
        if entry.flags != 1 && !(index == 7 && entry.flags == 2) {
            return Ok(());
        }
        coverage[index].matched += 1;
        match inspect(&backup, &entry, index) {
            Ok(items) => {
                coverage[index].inspected += 1;
                for (title, explanation) in items {
                    if findings.len() >= 10_000 {
                        return Err(Error::Limit("10,000 report findings"));
                    }
                    findings.push(Finding {
                        id: findings.len().to_string(),
                        category: CATEGORIES[index].into(),
                        title,
                        explanation: explanation.into(),
                        domain: entry.domain.clone(),
                        relative_path: entry.relative_path.clone(),
                        file_id: entry.file_id.clone(),
                    });
                }
            }
            Err(error) => {
                coverage[index].errors += 1;
                if warnings.len() >= 1_000 {
                    return Err(Error::Limit("1,000 scan warnings"));
                }
                warnings.push(format!(
                    "{} / {}: {error}",
                    entry.domain, entry.relative_path
                ));
            }
        }
        Ok(())
    })?;
    Ok(Report { schema_version: 1, backup: backup.info, findings, coverage, warnings,
        scope: "Review of selected backup artifacts, not a comprehensive compromise assessment. Missing artifacts and zero findings do not establish that a device is safe. Managed preferences, carrier settings, provisioning profiles, and Watch backups are inventory-only checks." })
}

fn error_json(code: &str, message: &str) -> String {
    serde_json::json!({"schema_version": 1, "error": {"code": code, "message": message}})
        .to_string()
}

/// Scan a backup and return owned UTF-8 JSON. Call off the UI thread.
///
/// # Safety
/// `path` must be null or point to a valid NUL-terminated UTF-8 string.
/// A non-null password must remain readable for `password_len` bytes for this
/// call. Null means no password; non-null with zero length means an empty password.
/// The result must be released exactly once using `isafety_string_free`.
#[no_mangle]
pub unsafe extern "C" fn isafety_scan_backup(
    path: *const c_char,
    password: *const u8,
    password_len: usize,
) -> *mut c_char {
    let output = std::panic::catch_unwind(|| {
        if path.is_null() || password_len > 1024 || (password.is_null() && password_len != 0) {
            return error_json("invalid_argument", "Invalid path or password arguments.");
        }
        let Ok(path) = (unsafe { CStr::from_ptr(path) }).to_str() else {
            return error_json("invalid_argument", "Backup path must be UTF-8.");
        };
        let password = if password.is_null() {
            None
        } else {
            Some(Zeroizing::new(
                unsafe { std::slice::from_raw_parts(password, password_len) }.to_vec(),
            ))
        };
        match scan(
            Path::new(path),
            password.as_ref().map(|value| value.as_slice()),
        ) {
            Ok(report) => serde_json::to_string(&report).unwrap_or_else(|_| {
                error_json("internal_error", "Could not serialize the scan report.")
            }),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    })
    .unwrap_or_else(|_| error_json("internal_error", "The scan stopped unexpectedly."));
    CString::new(output)
        .expect("JSON contains no literal NUL")
        .into_raw()
}

/// Release a returned JSON string; null is permitted.
///
/// # Safety
/// Pointer must be null or an unfreed pointer returned by `isafety_scan_backup`.
#[no_mangle]
pub unsafe extern "C" fn isafety_string_free(value: *mut c_char) {
    if !value.is_null() {
        let mut bytes = unsafe { CString::from_raw(value) }.into_bytes_with_nul();
        bytes.zeroize();
    }
}

/// Wipe caller-owned bytes without releasing their allocation.
///
/// # Safety
/// A non-null pointer must be exclusively writable for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn isafety_clear_bytes(value: *mut u8, length: usize) {
    if !value.is_null() {
        unsafe { std::slice::from_raw_parts_mut(value, length) }.zeroize();
    }
}
