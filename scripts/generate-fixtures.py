"""Generate synthetic, non-personal backups using Python/OpenSSL, independent of Rust.

Run with a Python environment containing cryptography. Low PBKDF counts keep tests
fast; these fixtures must never be used as an encryption-strength example.
"""
import hashlib
import plistlib
import sqlite3
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.padding import PKCS7

ROOT = Path(__file__).resolve().parents[1] / "crates/ibackup/tests/fixtures"
PASSWORD = "fixture-password-🔐".encode()


def tlv(tag, value):
    if isinstance(value, int):
        value = struct.pack(">I", value)
    return tag.encode() + struct.pack(">I", len(value)) + value


def encrypt(key, plaintext):
    padder = PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return cipher.update(data) + cipher.finalize()


def write_plist(path, value):
    path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))


def generate(name, encrypted, modern=True, password=PASSWORD):
    folder = ROOT / name
    folder.mkdir(parents=True, exist_ok=True)
    db_path = folder / "Manifest.db"
    db_path.unlink(missing_ok=True)
    class_key, manifest_key, file_key = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
    salt, aux_salt = b"test-salt-01234567890", b"test-aux-salt-0123456"
    initial = hashlib.pbkdf2_hmac("sha256", password, aux_salt, 1000, 32) if modern else password
    derived = hashlib.pbkdf2_hmac("sha1", initial, salt, 100, 32)
    bag = b"".join(tlv(k, v) for k, v in [("VERS", 3), ("TYPE", 1), ("UUID", bytes(16)), ("WRAP", 2), ("SALT", salt), ("ITER", 100)])
    if modern:
        bag += tlv("DPSL", aux_salt) + tlv("DPIC", 1000)
    bag += b"".join(tlv(k, v) for k, v in [("UUID", bytes([1])*16), ("CLAS", 4), ("WRAP", 2), ("KTYP", 0), ("WPKY", aes_key_wrap(derived, class_key))])
    persistent = lambda key: struct.pack("<I", 4) + aes_key_wrap(class_key, key)
    manifest = {"IsEncrypted": encrypted, "Version": "9.1"}
    if encrypted:
        manifest.update(BackupKeyBag=bag, ManifestKey=persistent(manifest_key))
    write_plist(folder / "Manifest.plist", manifest)
    write_plist(folder / "Info.plist", {"Device Name": "Fixture iPhone", "Product Type": "iPhone15,2", "Product Version": "18.0"})
    write_plist(folder / "Status.plist", {"SnapshotState": "finished"})
    entries = [
        ("SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles", "Library/ConfigurationProfiles/profile-fixture.plist", {"PayloadDisplayName": "Example configuration", "PayloadIdentifier": "org.example.fixture"}),
        ("HomeDomain", "Library/Preferences/com.apple.mobile.ldpair.plist", {"fixture-computer": {}}),
        ("DatabaseDomain", "com.apple.xpc.launchd/disabled.plist", {"org.example.disabled": True, "org.example.enabled": False}),
        ("SysSharedContainerDomain-systemgroup.com.apple.bluetooth", "Library/Preferences/com.apple.MobileBluetooth.devices.plist", {"00:11:22:33:44:55": {}}),
    ]
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    for domain, path, contents in entries:
        file_id = hashlib.sha1(f"{domain}-{path}".encode()).hexdigest()
        payload = plistlib.dumps(contents, fmt=plistlib.FMT_BINARY)
        metadata = {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": plistlib.UID(1)}, "$objects": ["$null", {"Size": len(payload), "ProtectionClass": 4, "EncryptionKey": plistlib.UID(2)}, {"NS.data": persistent(file_key)}]}
        connection.execute("INSERT INTO Files VALUES (?, ?, ?, 1, ?)", (file_id, domain, path, plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY)))
        target = folder / file_id[:2] / file_id
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(encrypt(file_key, payload) if encrypted else payload)
    connection.commit()
    connection.close()
    if encrypted:
        db_path.write_bytes(encrypt(manifest_key, db_path.read_bytes()))


if __name__ == "__main__":
    generate("plain", False)
    generate("encrypted-modern", True)
    generate("encrypted-legacy-kdf", True, modern=False)
    generate("encrypted-empty-password", True, password=b"")
