//! A minimal, dependency-free ZIP reader/writer restricted to **store** mode
//! (compression method 0).
//!
//! rsupd artifacts are already zstd-compressed individually, so the container
//! only needs to bundle and index them — deflate would waste cycles. This keeps
//! a real `.zip` (inspectable with `unzip`) without pulling an external crate.
//! Only the subset of the format we emit is supported: no ZIP64, no encryption,
//! no data descriptors, entries under 4 GiB.

use crate::error::{Error, Result};

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const VERSION: u16 = 20;

/// Builds a store-mode ZIP archive in memory.
pub struct ZipWriter {
    buf: Vec<u8>,
    entries: Vec<CentralEntry>,
}

struct CentralEntry {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
}

impl ZipWriter {
    /// Creates an empty archive builder.
    pub fn new() -> Self {
        ZipWriter {
            buf: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Appends one stored file.
    pub fn add(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let size = u32::try_from(data.len())
            .map_err(|_| Error::Other(format!("zip entry {name:?} exceeds 4 GiB")))?;
        let name_bytes = name.as_bytes();
        let name_len = u16::try_from(name_bytes.len())
            .map_err(|_| Error::Other(format!("zip entry name too long: {name:?}")))?;
        let crc = crc32(data);
        let offset = u32::try_from(self.buf.len())
            .map_err(|_| Error::Other("zip archive exceeds 4 GiB".into()))?;

        // Local file header.
        self.buf.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        self.buf.extend_from_slice(&VERSION.to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // method: store
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        self.buf.extend_from_slice(&crc.to_le_bytes());
        self.buf.extend_from_slice(&size.to_le_bytes()); // compressed
        self.buf.extend_from_slice(&size.to_le_bytes()); // uncompressed
        self.buf.extend_from_slice(&name_len.to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        self.buf.extend_from_slice(name_bytes);
        self.buf.extend_from_slice(data);

        self.entries.push(CentralEntry {
            name: name.to_string(),
            crc,
            size,
            offset,
        });
        Ok(())
    }

    /// Finalizes the archive, appending the central directory and EOCD, and
    /// returns the complete bytes.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let cd_offset = u32::try_from(self.buf.len())
            .map_err(|_| Error::Other("zip archive exceeds 4 GiB".into()))?;

        for e in &self.entries {
            let name_bytes = e.name.as_bytes();
            let name_len = name_bytes.len() as u16;
            self.buf.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            self.buf.extend_from_slice(&VERSION.to_le_bytes()); // version made by
            self.buf.extend_from_slice(&VERSION.to_le_bytes()); // version needed
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // method
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
            self.buf.extend_from_slice(&e.crc.to_le_bytes());
            self.buf.extend_from_slice(&e.size.to_le_bytes()); // compressed
            self.buf.extend_from_slice(&e.size.to_le_bytes()); // uncompressed
            self.buf.extend_from_slice(&name_len.to_le_bytes());
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // disk start
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            self.buf.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            self.buf.extend_from_slice(&e.offset.to_le_bytes());
            self.buf.extend_from_slice(name_bytes);
        }

        let cd_size = u32::try_from(self.buf.len() - cd_offset as usize)
            .map_err(|_| Error::Other("zip central directory exceeds 4 GiB".into()))?;
        let count = u16::try_from(self.entries.len())
            .map_err(|_| Error::Other("too many zip entries".into()))?;

        self.buf.extend_from_slice(&EOCD_SIG.to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
        self.buf.extend_from_slice(&count.to_le_bytes());
        self.buf.extend_from_slice(&count.to_le_bytes());
        self.buf.extend_from_slice(&cd_size.to_le_bytes());
        self.buf.extend_from_slice(&cd_offset.to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // comment len

        Ok(self.buf)
    }
}

impl Default for ZipWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads a store-mode ZIP archive from an in-memory buffer.
pub struct ZipReader<'a> {
    data: &'a [u8],
    entries: Vec<ReadEntry>,
}

struct ReadEntry {
    name: String,
    offset: u32,
    size: u32,
    crc: u32,
}

impl<'a> ZipReader<'a> {
    /// Parses the central directory of `data`.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let eocd = find_eocd(data)?;
        let count = read_u16(data, eocd + 10)? as usize;
        let cd_offset = read_u32(data, eocd + 16)? as usize;

        let mut entries = Vec::with_capacity(count);
        let mut p = cd_offset;
        for _ in 0..count {
            if read_u32(data, p)? != CENTRAL_SIG {
                return Err(Error::Malformed("bad central directory signature".into()));
            }
            let method = read_u16(data, p + 10)?;
            let crc = read_u32(data, p + 16)?;
            let comp_size = read_u32(data, p + 20)?;
            let uncomp_size = read_u32(data, p + 24)?;
            let name_len = read_u16(data, p + 28)? as usize;
            let extra_len = read_u16(data, p + 30)? as usize;
            let comment_len = read_u16(data, p + 32)? as usize;
            let local_offset = read_u32(data, p + 42)?;
            let name_start = p
                .checked_add(46)
                .ok_or_else(|| Error::Malformed("zip offset overflow".into()))?;
            let name = std::str::from_utf8(slice(data, name_start, name_len)?)
                .map_err(|_| Error::Malformed("non-utf8 zip entry name".into()))?
                .to_string();
            if method != 0 {
                return Err(Error::Malformed(format!(
                    "zip entry {name:?} uses unsupported compression method {method}"
                )));
            }
            if comp_size != uncomp_size {
                return Err(Error::Malformed(format!(
                    "zip entry {name:?} is not stored"
                )));
            }
            entries.push(ReadEntry {
                name,
                offset: local_offset,
                size: comp_size,
                crc,
            });
            p = name_start
                .checked_add(name_len)
                .and_then(|v| v.checked_add(extra_len))
                .and_then(|v| v.checked_add(comment_len))
                .ok_or_else(|| Error::Malformed("zip offset overflow".into()))?;
        }
        Ok(ZipReader { data, entries })
    }

    /// Lists entry names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// Extracts the stored bytes of `name`, verifying its CRC-32.
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let e = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| Error::Malformed(format!("zip entry not found: {name:?}")))?;
        let off = e.offset as usize;
        if read_u32(self.data, off)? != LOCAL_SIG {
            return Err(Error::Malformed("bad local file header signature".into()));
        }
        let name_len = read_u16(self.data, off + 26)? as usize;
        let extra_len = read_u16(self.data, off + 28)? as usize;
        let data_start = off
            .checked_add(30)
            .and_then(|v| v.checked_add(name_len))
            .and_then(|v| v.checked_add(extra_len))
            .ok_or_else(|| Error::Malformed("zip offset overflow".into()))?;
        let bytes = slice(self.data, data_start, e.size as usize)?.to_vec();
        if crc32(&bytes) != e.crc {
            return Err(Error::Malformed(format!("zip entry {name:?} CRC mismatch")));
        }
        Ok(bytes)
    }
}

fn find_eocd(data: &[u8]) -> Result<usize> {
    // EOCD is 22 bytes + a (here always empty) comment. Scan backwards.
    if data.len() < 22 {
        return Err(Error::Malformed("file too small to be a zip".into()));
    }
    let min = data.len().saturating_sub(22 + 0xFFFF);
    for i in (min..=data.len() - 22).rev() {
        if read_u32(data, i)? == EOCD_SIG {
            return Ok(i);
        }
    }
    Err(Error::Malformed(
        "zip end-of-central-directory not found".into(),
    ))
}

fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    // Use checked arithmetic so a malicious zip can't wrap `start + len` (which
    // would panic in debug or produce a wrapped range) on 32-bit targets.
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::Malformed("zip read out of bounds".into()))?;
    data.get(start..end)
        .ok_or_else(|| Error::Malformed("zip read out of bounds".into()))
}

fn read_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(data, at, 2)?.try_into().unwrap()))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(data, at, 4)?.try_into().unwrap()))
}

// --- CRC-32 (IEEE / zip, reflected poly 0xEDB88320) ---------------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn roundtrip_store() {
        let mut w = ZipWriter::new();
        w.add("manifest.cbor", b"hello manifest").unwrap();
        w.add("bin/x/app.zst", &[1u8, 2, 3, 4, 5]).unwrap();
        let bytes = w.finish().unwrap();

        let r = ZipReader::new(&bytes).unwrap();
        let names: Vec<_> = r.names().collect();
        assert_eq!(names, vec!["manifest.cbor", "bin/x/app.zst"]);
        assert_eq!(r.read("manifest.cbor").unwrap(), b"hello manifest");
        assert_eq!(r.read("bin/x/app.zst").unwrap(), vec![1, 2, 3, 4, 5]);
        assert!(r.read("missing").is_err());
    }
}
