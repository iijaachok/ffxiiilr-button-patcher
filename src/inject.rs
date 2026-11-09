//! Append a payload to a `white_img` archive and repoint its filelist entry
//! (port of Cocoon's `injectFile2`).

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::filelist::{Filelist, InfoString, SECTOR, zlib_compress};
use crate::whitecrypt;

/// Virtual path of the archive slot the mod replaces.
pub const VIRTUAL_PATH: &str = "gui/resident/system.win32.imgb";

pub struct InjectOptions {
    pub filelist_path: PathBuf,
    pub white_img_path: PathBuf,
    pub payload: Vec<u8>,
    pub dry_run: bool,
}

#[derive(Debug)]
pub struct InjectReport {
    pub entry_index: usize,
    pub old_info: String,
    pub new_info: String,
    pub raw_size: usize,
    pub stored_size: usize,
    pub new_addr_sector: u64,
    pub new_filelist_size: usize,
    pub new_white_img_size: u64,
}

/// Read a whole file.
fn read_file(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).with_context(|| format!("reading {}", p.display()))
}

/// Replace every occurrence of `needle` with `repl` inside `hay`.
fn replace_all(hay: &[u8], needle: &[u8], repl: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(repl);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

pub fn inject(opts: &InjectOptions) -> Result<InjectReport> {
    // 1. decrypt + parse the filelist
    let fl_enc = read_file(&opts.filelist_path)?;
    let dec = whitecrypt::decrypt_filelist(&fl_enc)
        .context("decrypting filelist (is it already patched, or the wrong file?)")?;
    let mut fl = Filelist::parse(dec)?;

    // 2. locate the entry
    let (entry_index, info) = fl
        .find_entry(VIRTUAL_PATH)
        .with_context(|| format!("virtual path {VIRTUAL_PATH:?} not found in filelist"))?;
    let old_info = info.to_string();

    // 3. decide placement in white_img
    let wi_len = std::fs::metadata(&opts.white_img_path)
        .with_context(|| format!("stat {}", opts.white_img_path.display()))?
        .len();
    let num3 = wi_len.div_ceil(SECTOR) * SECTOR;
    let new_addr_sector = num3 / SECTOR;

    let stored = if info.decompressed_size == info.compressed_size {
        opts.payload.clone()
    } else {
        zlib_compress(&opts.payload)
    };
    let payload_len = opts.payload.len();
    let stored_len = stored.len();

    let new_info = InfoString {
        address_sector: u32::try_from(new_addr_sector)
            .context("white_img too large for 32-bit sector address")?,
        decompressed_size: payload_len as u32,
        compressed_size: stored_len as u32,
        path: VIRTUAL_PATH.to_string(),
    }
    .to_string();

    // 4. string-table update + strPtr rewrite
    let old_bytes = old_info.as_bytes();
    let new_bytes = new_info.as_bytes();
    let vpath_bytes = VIRTUAL_PATH.as_bytes();

    let mut num9 = 0usize;
    let mut updates: Vec<(usize, u16)> = Vec::new();
    for ci in 0..fl.num_chunks {
        let chunk = fl.chunks[ci].clone();
        let strings: Vec<&[u8]> = Filelist::chunk_strings(&chunk).clone();
        if chunk.windows(vpath_bytes.len()).any(|w| w == vpath_bytes) {
            let flag = ci % 2 != 0;
            let first = strings.first().copied().unwrap_or(&[]);
            let list10: Vec<usize> = strings
                .iter()
                .enumerate()
                .filter(|(_, s)| **s == first)
                .map(|(i, _)| i)
                .collect();

            let new_chunk = replace_all(&chunk, old_bytes, new_bytes);
            let array6: Vec<&[u8]> = Filelist::chunk_strings(&new_chunk);

            let mut num14: u32 = if flag { 0x8000 } else { 0 };
            let mut list8: Vec<u16> = Vec::with_capacity(array6.len());
            for s in &array6 {
                list8.push((num14 & 0xFFFF) as u16);
                num14 = num14.wrapping_add(s.len() as u32 + 1);
            }
            let base = num9 + list10.first().copied().unwrap_or(0);
            for (j, off) in list8.iter().enumerate() {
                updates.push((base + j, *off));
            }
            fl.chunks[ci] = new_chunk;
        }
        num9 += strings.len();
    }
    for (idx, val) in &updates {
        if *idx < fl.count {
            fl.set_string_pointer(*idx, *val);
        }
    }

    // 5. rebuild + encrypt
    let rebuilt = fl.rebuild();
    let enc = whitecrypt::encrypt_filelist(&rebuilt)?;

    let new_white_img_size =
        num3 + stored_len as u64 + (SECTOR - ((num3 + stored_len as u64) % SECTOR)) % SECTOR;
    let report = InjectReport {
        entry_index,
        old_info,
        new_info,
        raw_size: payload_len,
        stored_size: stored_len,
        new_addr_sector,
        new_filelist_size: enc.len(),
        new_white_img_size,
    };

    if opts.dry_run {
        return Ok(report);
    }

    // 6a. write the filelist (atomic: temp + rename)
    let tmp = opts.filelist_path.with_extension("tmp-write");
    std::fs::write(&tmp, &enc).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &opts.filelist_path)
        .with_context(|| format!("replacing {}", opts.filelist_path.display()))?;

    // 6b. append payload to the white_img in place
    append_payload(&opts.white_img_path, num3, &stored)?;

    Ok(report)
}

/// Append `stored` at offset `num3` of `path`, zero-padding to 2048 boundaries.
fn append_payload(path: &Path, num3: u64, stored: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} for append", path.display()))?;
    let len = f.metadata()?.len();
    if num3 > len {
        f.seek(SeekFrom::Start(len))?;
        let zeros = vec![0u8; (num3 - len) as usize];
        f.write_all(&zeros)?;
    } else {
        f.seek(SeekFrom::Start(num3))?;
    }
    f.write_all(stored).context("appending payload")?;
    let pos = f.stream_position()?;
    let pad = (SECTOR - pos % SECTOR) % SECTOR;
    if pad != 0 {
        f.write_all(&vec![0u8; pad as usize])?;
    }
    f.flush()?;
    Ok(())
}

/// Back up a file to `<name>.original` unless the backup already exists.
pub fn backup_once(path: &Path) -> Result<()> {
    let bak = PathBuf::from(format!("{}.original", path.display()));
    if !bak.exists() {
        std::fs::copy(path, &bak).with_context(|| format!("backing up {}", path.display()))?;
    }
    Ok(())
}

/// Restore a file from its `.original` backup, if present. Returns true if restored.
pub fn restore(path: &Path) -> Result<bool> {
    let bak = PathBuf::from(format!("{}.original", path.display()));
    if !bak.exists() {
        return Ok(false);
    }
    std::fs::copy(&bak, path).with_context(|| format!("restoring {}", path.display()))?;
    Ok(true)
}
