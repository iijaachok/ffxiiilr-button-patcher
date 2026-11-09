//! Parse and rebuild the LR/XIII filelist container.
//!
//! Layout (relative offsets; header pointers are relative to byte 32):
//! `[0..32)`   plaintext preamble (`dataSize` BE at 16, magic at 20)
//! `[32..44)`  zlibInfoPointer(i32), zlibDataPointer(i32), resourceCount(i32)
//! `[44..44+8*n)` entries (see [`Entry`])
//! `[32+zi .. 32+zd)` zlib info table (12 bytes/chunk)
//! `[32+zd ..)`       zlib-compressed string-table chunks
//! last 8 bytes of the encrypted region: `[dataSize LE][checksum LE]`
//! then an 8-byte unencrypted remainder.

use anyhow::{Context, Result, bail};
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib;

pub const HEADER_SIZE: usize = 44;
pub const ENTRY_SIZE: usize = 8;
pub const INFO_SIZE: usize = 12;
pub const SECTOR: u64 = 2048;

/// One 8-byte resource entry.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // package_index/type_flag are parsed for completeness
pub struct Entry {
    pub package_index: u32,
    pub string_pointer: u16,
    pub chunk_index: u8,
    pub type_flag: u8,
}

/// Parsed representation of the decrypted filelist.
pub struct Filelist {
    /// Decrypted filelist bytes (entries are patched directly here).
    pub dec: Vec<u8>,
    /// Number of resource entries.
    pub count: usize,
    /// Number of compressed string-table chunks.
    pub num_chunks: usize,
    /// Decompressed string-table chunks (mutable: inject replaces a string).
    pub chunks: Vec<Vec<u8>>,
}

pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_to_vec_zlib(data).map_err(|e| anyhow::anyhow!("zlib decompress failed: {e:?}"))
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    // miniz_oxide level 10 == best compression.
    compress_to_vec_zlib(data, 10)
}

impl Filelist {
    /// Parse a *decrypted* filelist.
    pub fn parse(dec: Vec<u8>) -> Result<Self> {
        if dec.len() < HEADER_SIZE {
            bail!("filelist too small ({})", dec.len());
        }
        let magic = u32::from_le_bytes(dec[20..24].try_into().unwrap());
        if magic != 0x1DE0_3478 {
            bail!("bad filelist magic {magic:#010x} (not decrypted, or wrong file)");
        }
        let zlib_info_ptr = u32::from_le_bytes(dec[32..36].try_into().unwrap()) as usize;
        let zlib_data_ptr = u32::from_le_bytes(dec[36..40].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(dec[40..44].try_into().unwrap()) as usize;
        if zlib_data_ptr <= zlib_info_ptr {
            bail!("invalid pointer table ({zlib_info_ptr:#x} >= {zlib_data_ptr:#x})");
        }
        let num_chunks = (zlib_data_ptr - zlib_info_ptr) / INFO_SIZE;

        let mut chunks = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let base = 32 + zlib_info_ptr + i * INFO_SIZE;
            let dlen = u32::from_le_bytes(dec[base..base + 4].try_into().unwrap()) as usize;
            let clen = u32::from_le_bytes(dec[base + 4..base + 8].try_into().unwrap()) as usize;
            let ptr = u32::from_le_bytes(dec[base + 8..base + 12].try_into().unwrap()) as usize;
            let start = 32 + zlib_data_ptr + ptr;
            let raw = dec
                .get(start..start + clen)
                .context("chunk extends past end of file")?;
            let chunk =
                zlib_decompress(raw).with_context(|| format!("chunk {i} did not inflate"))?;
            if chunk.len() != dlen {
                bail!(
                    "chunk {i}: decompressed {} bytes, header says {dlen}",
                    chunk.len()
                );
            }
            chunks.push(chunk);
        }

        Ok(Self {
            dec,
            count,
            num_chunks,
            chunks,
        })
    }

    pub fn entry(&self, n: usize) -> Entry {
        let b = HEADER_SIZE + n * ENTRY_SIZE;
        Entry {
            package_index: u32::from_le_bytes(self.dec[b..b + 4].try_into().unwrap()),
            string_pointer: u16::from_le_bytes(self.dec[b + 4..b + 6].try_into().unwrap()),
            chunk_index: self.dec[b + 6],
            type_flag: self.dec[b + 7],
        }
    }

    /// Patch an entry's `string_pointer` field in place.
    pub fn set_string_pointer(&mut self, n: usize, value: u16) {
        let b = HEADER_SIZE + n * ENTRY_SIZE + 4;
        self.dec[b..b + 2].copy_from_slice(&value.to_le_bytes());
    }

    /// Null-separated strings of one chunk (trailing empty element dropped).
    pub fn chunk_strings(chunk: &[u8]) -> Vec<&[u8]> {
        let mut parts: Vec<&[u8]> = chunk.split(|&b| b == 0).collect();
        if parts.last().is_some_and(|p| p.is_empty()) {
            parts.pop();
        }
        parts
    }

    /// All strings across all chunks, in order, tagged with their chunk index.
    pub fn global_strings(&self) -> Vec<(usize, Vec<u8>)> {
        let mut out = Vec::new();
        for (ci, chunk) in self.chunks.iter().enumerate() {
            for s in Self::chunk_strings(chunk) {
                out.push((ci, s.to_vec()));
            }
        }
        out
    }

    /// Look up the entry index whose info-string path equals `vpath`, and parse it.
    pub fn find_entry(&self, vpath: &str) -> Option<(usize, InfoString)> {
        let globals = self.global_strings();
        globals
            .iter()
            .take(self.count)
            .enumerate()
            .find_map(|(n, (_, s))| {
                let info = InfoString::parse(s)?;
                (info.path == vpath).then_some((n, info))
            })
    }

    /// Rebuild the decrypted filelist bytes (info table + padded chunk data).
    pub fn rebuild(&self) -> Vec<u8> {
        let mut comp_chunks = Vec::with_capacity(self.num_chunks);
        for c in &self.chunks {
            comp_chunks.push(zlib_compress(c));
        }

        let mut info = Vec::with_capacity(self.num_chunks * INFO_SIZE);
        let mut offset: u32 = 0;
        for (c, comp) in self.chunks.iter().zip(&comp_chunks) {
            info.extend_from_slice(&(c.len() as u32).to_le_bytes());
            info.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            info.extend_from_slice(&offset.to_le_bytes());
            offset += comp.len() as u32;
        }

        let head_len = HEADER_SIZE + self.count * ENTRY_SIZE;
        let mut head = self.dec[..head_len].to_vec();

        let mut data = info;
        for comp in &comp_chunks {
            data.extend_from_slice(comp);
        }
        let prefix = head_len - 32; // zi/zd/count + entries, relative to offset 32
        while !(prefix + data.len()).is_multiple_of(8) {
            data.push(0);
        }
        let num18 = (prefix + data.len()) as u32;

        head[16..20].copy_from_slice(&num18.to_be_bytes()); // dataSize BE

        let mut out = Vec::with_capacity(32 + num18 as usize + 8 + 8);
        out.extend_from_slice(&head[..32]);
        out.extend_from_slice(&head[32..]); // zi/zd/count + patched entries
        out.extend_from_slice(&data);
        out.extend_from_slice(&num18.to_le_bytes()); // dataSize marker (LE)
        out.extend_from_slice(&[0u8; 4]); // checksum slot (filled by encrypt)
        out.extend_from_slice(&[0u8; 8]); // unencrypted remainder
        out
    }
}

/// Parsed `addr:decompressed:compressed:path` info string.
#[derive(Clone, Debug)]
pub struct InfoString {
    pub address_sector: u32,
    pub decompressed_size: u32,
    pub compressed_size: u32,
    pub path: String,
}

impl InfoString {
    pub fn parse(s: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(s).ok()?;
        let mut it = s.splitn(4, ':');
        let addr = u32::from_str_radix(it.next()?, 16).ok()?;
        let dec = u32::from_str_radix(it.next()?, 16).ok()?;
        let comp = u32::from_str_radix(it.next()?, 16).ok()?;
        let path = it.next()?.to_string();
        Some(Self {
            address_sector: addr,
            decompressed_size: dec,
            compressed_size: comp,
            path,
        })
    }
}

impl std::fmt::Display for InfoString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{}",
            self.address_sector, self.decompressed_size, self.compressed_size, self.path
        )
    }
}
