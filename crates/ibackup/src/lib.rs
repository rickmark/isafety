//! Read-only access to local Finder/iTunes backups. See docs/backup-encryption.md.
mod crypto;

use plist::Value;
use rusqlite::{Connection, MAIN_DB};
use rustix::fs::{openat, Mode, OFlags};
use serde::Serialize;
use std::{
    fs::File,
    io::{Cursor, Read},
    path::{Component, Path},
};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("This backup is encrypted. Enter its backup password.")]
    PasswordRequired,
    #[error("Could not unlock the backup: incorrect password or damaged keybag.")]
    PasswordOrKeybag,
    #[error("Cryptographic validation failed; the backup may be damaged.")]
    Crypto,
    #[error("Invalid backup: {0}.")]
    Format(&'static str),
    #[error("Unsupported backup: {0}.")]
    Unsupported(&'static str),
    #[error("Backup exceeds the supported limit: {0}.")]
    Limit(&'static str),
    #[error("Could not read backup data: {0}")]
    Io(#[from] std::io::Error),
    #[error("Could not parse backup property list: {0}")]
    Plist(#[from] plist::Error),
    #[error("Could not read backup manifest: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PasswordRequired => "password_required",
            Self::PasswordOrKeybag => "password_or_keybag",
            Self::Crypto => "decryption_failed",
            Self::Unsupported(_) => "unsupported_backup",
            Self::Limit(_) => "resource_limit",
            _ => "invalid_backup",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BackupInfo {
    pub device_name: String,
    pub product_type: String,
    pub product_version: String,
    pub encrypted: bool,
    pub file_count: u64,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub file_id: String,
    pub domain: String,
    pub relative_path: String,
    pub flags: u32,
}

pub struct Backup {
    directory: File,
    database: Connection,
    keybag: Option<crypto::Keybag>,
    pub info: BackupInfo,
    pub warnings: Vec<String>,
}

const PLIST_LIMIT: usize = 32 * 1024 * 1024;
const MANIFEST_LIMIT: usize = 512 * 1024 * 1024;

// Open each component relative to a directory descriptor: no symlinks, traversal,
// or path-check/open race. NONBLOCK avoids hanging on a malicious FIFO.
fn read(directory: &File, relative: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let components: Vec<_> = relative.components().collect();
    let mut parent = directory.try_clone()?;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(Error::Format("unsafe backup path"));
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if index + 1 < components.len() {
            flags |= OFlags::DIRECTORY;
        }
        parent =
            File::from(openat(&parent, *name, flags, Mode::empty()).map_err(std::io::Error::from)?);
    }
    let metadata = parent.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Format("expected a regular backup file"));
    }
    if metadata.len() > limit as u64 {
        return Err(Error::Limit("file size"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    parent.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Limit("file size"));
    }
    Ok(bytes)
}

fn dictionary(value: &Value) -> Result<&plist::Dictionary> {
    value
        .as_dictionary()
        .ok_or(Error::Format("expected a property-list dictionary"))
}

fn data<'a>(value: &'a Value, key: &str) -> Result<&'a [u8]> {
    dictionary(value)?
        .get(key)
        .and_then(Value::as_data)
        .ok_or(Error::Format("missing encryption data"))
}

impl Backup {
    pub fn open(path: &Path, password: Option<&[u8]>) -> Result<Self> {
        let directory = File::open(path)?;
        if !directory.metadata()?.is_dir() {
            return Err(Error::Format("choose a backup directory"));
        }
        let manifest = Value::from_reader(Cursor::new(&*read(
            &directory,
            Path::new("Manifest.plist"),
            PLIST_LIMIT,
        )?))?;
        let encrypted = dictionary(&manifest)?
            .get("IsEncrypted")
            .and_then(Value::as_boolean)
            .ok_or(Error::Format("missing IsEncrypted flag"))?;
        let keybag = if encrypted {
            Some(crypto::Keybag::unlock(
                data(&manifest, "BackupKeyBag")?,
                password.ok_or(Error::PasswordRequired)?,
            )?)
        } else {
            None
        };
        // Do not silently ignore an unfinished SQLite transaction.
        for suffix in ["Manifest.db-wal", "Manifest.db-journal"] {
            if path.join(suffix).symlink_metadata().is_ok() {
                return Err(Error::Unsupported(
                    "manifest has a journal; use a completed backup snapshot",
                ));
            }
        }
        let mut bytes = read(&directory, Path::new("Manifest.db"), MANIFEST_LIMIT)?;
        if let Some(keys) = &keybag {
            crypto::decrypt(
                &mut bytes,
                &*keys.unwrap_persistent(data(&manifest, "ManifestKey")?)?,
            )?;
        }
        if !bytes.starts_with(b"SQLite format 3\0") {
            return Err(Error::Format("Manifest.db is not a SQLite database"));
        }
        let mut database = Connection::open_in_memory()?;
        database.deserialize_read_exact(MAIN_DB, Cursor::new(&*bytes), bytes.len(), true)?;
        database.execute_batch(
            "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;",
        )?;
        let table_type: String = database.query_row(
            "SELECT type FROM sqlite_schema WHERE name='Files'",
            [],
            |row| row.get(0),
        )?;
        if table_type != "table" {
            return Err(Error::Format("Files must be a table"));
        }
        let integrity: String =
            database.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(Error::Format("manifest integrity check failed"));
        }
        database.prepare("SELECT fileID, domain, relativePath, flags, file FROM Files LIMIT 0")?;
        let file_count: u64 =
            database.query_row("SELECT COUNT(*) FROM Files", [], |row| row.get(0))?;
        if file_count > 2_000_000 {
            return Err(Error::Limit("manifest entries"));
        }
        let info = Value::from_reader(Cursor::new(&*read(
            &directory,
            Path::new("Info.plist"),
            PLIST_LIMIT,
        )?))?;
        let info = dictionary(&info)?;
        let text = |key: &str| {
            info.get(key)
                .and_then(Value::as_string)
                .unwrap_or("Unknown")
                .to_string()
        };
        let mut warnings = Vec::new();
        match read(&directory, Path::new("Status.plist"), PLIST_LIMIT) {
            Ok(bytes) => {
                let status = Value::from_reader(Cursor::new(&*bytes))?;
                if dictionary(&status)?
                    .get("SnapshotState")
                    .and_then(Value::as_string)
                    != Some("finished")
                {
                    warnings.push(
                        "The backup is not marked finished; some evidence may be missing.".into(),
                    );
                }
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => warnings
                .push("Status.plist is absent; backup completion could not be verified.".into()),
            Err(e) => return Err(e),
        }
        Ok(Self {
            directory,
            database,
            keybag,
            warnings,
            info: BackupInfo {
                device_name: text("Device Name"),
                product_type: text("Product Type"),
                product_version: text("Product Version"),
                encrypted,
                file_count,
            },
        })
    }

    pub fn visit_entries(&self, mut visitor: impl FnMut(Entry) -> Result<()>) -> Result<()> {
        let mut query = self.database.prepare("SELECT fileID, domain, relativePath, flags FROM Files ORDER BY domain, relativePath, fileID")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let entry = Entry {
                file_id: row.get(0)?,
                domain: row.get(1)?,
                relative_path: row.get(2)?,
                flags: row.get(3)?,
            };
            if entry.file_id.len() != 40 || !entry.file_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Format("invalid file ID"));
            }
            if entry.domain.len() > 1024 || entry.relative_path.len() > 16384 {
                return Err(Error::Limit("manifest path length"));
            }
            visitor(entry)?;
        }
        Ok(())
    }

    pub fn read_file(&self, entry: &Entry) -> Result<Zeroizing<Vec<u8>>> {
        let id = &entry.file_id;
        if id.len() != 40 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Format("invalid file ID"));
        }
        if entry.flags != 1 {
            return Err(Error::Format("entry is not a regular file"));
        }
        let mut bytes = match read(&self.directory, &Path::new(&id[..2]).join(id), PLIST_LIMIT) {
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                read(&self.directory, Path::new(id), PLIST_LIMIT)?
            }
            result => result?,
        };
        if let Some(keys) = &self.keybag {
            let metadata: Vec<u8> = self.database.query_row(
                "SELECT file FROM Files WHERE fileID=?1 AND length(file)<=1048576",
                [id],
                |row| row.get(0),
            )?;
            let archive = Value::from_reader(Cursor::new(metadata))?;
            let objects = dictionary(&archive)?
                .get("$objects")
                .and_then(Value::as_array)
                .ok_or(Error::Format("missing archived metadata objects"))?;
            let resolve = |value: &Value| -> Result<Value> {
                match value.as_uid() {
                    Some(uid) => objects
                        .get(
                            usize::try_from(uid.get())
                                .map_err(|_| Error::Format("metadata reference overflow"))?,
                        )
                        .cloned()
                        .ok_or(Error::Format("invalid metadata reference")),
                    None => Ok(value.clone()),
                }
            };
            let root = dictionary(&archive)?
                .get("$top")
                .and_then(Value::as_dictionary)
                .and_then(|v| v.get("root"))
                .ok_or(Error::Format("missing archived metadata root"))?;
            let root = resolve(root)?;
            let record = dictionary(&root)?;
            let size = record
                .get("Size")
                .and_then(Value::as_unsigned_integer)
                .ok_or(Error::Format("missing file size"))?;
            if size > PLIST_LIMIT as u64 {
                return Err(Error::Limit("decrypted file size"));
            }
            // Empty files may have no encryption key and no ciphertext.
            if size == 0 && bytes.is_empty() {
                return Ok(bytes);
            }
            let key = resolve(
                record
                    .get("EncryptionKey")
                    .ok_or(Error::Format("missing file encryption key"))?,
            )?;
            let persistent = key
                .as_data()
                .or_else(|| {
                    key.as_dictionary()
                        .and_then(|v| v.get("NS.data"))
                        .and_then(Value::as_data)
                })
                .ok_or(Error::Format("invalid archived encryption key"))?;
            let class = record
                .get("ProtectionClass")
                .and_then(Value::as_unsigned_integer)
                .ok_or(Error::Format("missing protection class"))?;
            if persistent.len() != 44
                || u32::from_le_bytes(persistent[..4].try_into().unwrap()) as u64 != class
            {
                return Err(Error::Format("file protection class mismatch"));
            }
            crypto::decrypt(&mut bytes, &*keys.unwrap_persistent(persistent)?)?;
            if bytes.len() as u64 != size {
                return Err(Error::Format(
                    "decrypted size differs from manifest; evidence may be incomplete",
                ));
            }
        }
        Ok(bytes)
    }
}
