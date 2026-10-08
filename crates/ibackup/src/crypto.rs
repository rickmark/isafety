use std::collections::BTreeMap;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

type Fields = BTreeMap<[u8; 4], Vec<u8>>;
pub(crate) struct Keybag(BTreeMap<u32, Zeroizing<[u8; 32]>>);

fn integer(fields: &Fields, tag: &[u8; 4]) -> Result<u32> {
    let bytes = fields
        .get(tag)
        .ok_or(Error::Format("missing keybag field"))?;
    Ok(u32::from_be_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Format("invalid keybag integer"))?,
    ))
}

fn iterations(fields: &Fields, tag: &[u8; 4], maximum: u32) -> Result<u32> {
    let count = integer(fields, tag)?;
    if count == 0 || count > maximum {
        return Err(Error::Limit("key derivation iteration count"));
    }
    Ok(count)
}

fn salt<'a>(fields: &'a Fields, tag: &[u8; 4]) -> Result<&'a [u8]> {
    let value = fields
        .get(tag)
        .ok_or(Error::Format("missing keybag salt"))?;
    if value.is_empty() || value.len() > 64 {
        return Err(Error::Format("invalid keybag salt"));
    }
    Ok(value)
}

impl Keybag {
    pub(crate) fn unlock(blob: &[u8], password: &[u8]) -> Result<Self> {
        if blob.len() > 64 * 1024 {
            return Err(Error::Limit("keybag size"));
        }
        let mut header = Fields::new();
        let mut records: Vec<Fields> = Vec::new();
        let mut offset = 0;
        let mut seen_uuid = false;
        while offset < blob.len() {
            let prefix = blob
                .get(offset..offset + 8)
                .ok_or(Error::Format("truncated keybag header"))?;
            let tag: [u8; 4] = prefix[..4].try_into().unwrap();
            let length = u32::from_be_bytes(prefix[4..].try_into().unwrap()) as usize;
            offset += 8;
            let value = blob
                .get(
                    offset
                        ..offset
                            .checked_add(length)
                            .ok_or(Error::Format("keybag length overflow"))?,
                )
                .ok_or(Error::Format("truncated keybag value"))?;
            offset += length;
            if &tag == b"UUID" {
                if value.len() != 16 {
                    return Err(Error::Format("invalid keybag UUID"));
                }
                if seen_uuid {
                    records.push(Fields::new());
                }
                seen_uuid = true;
            }
            let target = records.last_mut().unwrap_or(&mut header);
            if target.insert(tag, value.to_vec()).is_some() {
                return Err(Error::Format("duplicate keybag field"));
            }
        }
        if integer(&header, b"TYPE")? != 1 {
            return Err(Error::Unsupported(
                "only local backup keybags are supported",
            ));
        }
        // Validate BOTH stages before doing expensive work on untrusted parameters.
        let rounds = iterations(&header, b"ITER", 1_000_000)?;
        let final_salt = salt(&header, b"SALT")?;
        let modern = header.contains_key(b"DPSL") || header.contains_key(b"DPIC");
        let mut stage1 = Zeroizing::new([0u8; 32]);
        let mut derived = Zeroizing::new([0u8; 32]);
        if modern {
            let count = iterations(&header, b"DPIC", 20_000_000)?;
            pbkdf2_hmac::<Sha256>(password, salt(&header, b"DPSL")?, count, &mut *stage1);
            pbkdf2_hmac::<Sha1>(&*stage1, final_salt, rounds, &mut *derived);
        } else {
            pbkdf2_hmac::<Sha1>(password, final_salt, rounds, &mut *derived);
        }
        let mut keys = BTreeMap::new();
        for record in records {
            let class = integer(&record, b"CLAS")?;
            let wrap = integer(&record, b"WRAP")?;
            // Device-bound and asymmetric classes cannot be unlocked with a backup password.
            if wrap != 2
                || record
                    .get(b"KTYP")
                    .is_some_and(|_| integer(&record, b"KTYP").unwrap_or(u32::MAX) != 0)
            {
                continue;
            }
            let wrapped = record
                .get(b"WPKY")
                .ok_or(Error::Format("missing wrapped class key"))?;
            let key = unwrap(&derived, wrapped).map_err(|_| Error::PasswordOrKeybag)?;
            if keys.insert(class, key).is_some() {
                return Err(Error::Format("duplicate protection class"));
            }
        }
        if keys.is_empty() {
            return Err(Error::Unsupported("no password-wrapped AES class keys"));
        }
        Ok(Self(keys))
    }

    pub(crate) fn unwrap_persistent(&self, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if bytes.len() != 44 {
            return Err(Error::Format(
                "persistent key must contain a class and 40 wrapped bytes",
            ));
        }
        let class = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let key = self.0.get(&class).ok_or(Error::Unsupported(
            "required protection class is unavailable or device-bound",
        ))?;
        unwrap(key, &bytes[4..])
    }
}

fn unwrap(key: &[u8; 32], wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.len() != 40 {
        return Err(Error::Format("invalid wrapped AES-256 key length"));
    }
    let mut result = Zeroizing::new([0u8; 32]);
    aes_kw::KekAes256::try_from(key.as_slice())
        .map_err(|_| Error::Crypto)?
        .unwrap(wrapped, &mut *result)
        .map_err(|_| Error::Crypto)?;
    Ok(result)
}

pub(crate) fn decrypt(bytes: &mut Zeroizing<Vec<u8>>, key: &[u8; 32]) -> Result<()> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
        return Err(Error::Format("invalid AES-CBC ciphertext length"));
    }
    let length = cbc::Decryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into())
        .decrypt_padded_mut::<Pkcs7>(bytes)
        .map_err(|_| Error::Crypto)?
        .len();
    bytes.truncate(length);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3394_aes256_vector_and_tampering() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut wrapped = [
            0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87,
            0xf8, 0x26, 0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7,
            0x1a, 0x99, 0xf4, 0x3b, 0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21,
        ];
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];
        assert_eq!(*unwrap(&key, &wrapped).unwrap(), expected);
        wrapped[5] ^= 1;
        assert!(unwrap(&key, &wrapped).is_err());
    }

    #[test]
    fn rejects_truncated_keybag_and_ciphertext() {
        for n in 1..8 {
            assert!(Keybag::unlock(&b"UUIDxxxx"[..n], b"test").is_err());
        }
        assert!(decrypt(&mut Zeroizing::new(vec![0; 17]), &[0; 32]).is_err());
    }
}
