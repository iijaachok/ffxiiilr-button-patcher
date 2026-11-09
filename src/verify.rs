use crate::cli::VerifyArgs;
use crate::filelist::{Filelist, SECTOR};
use crate::{inject, paths, whitecrypt};
use anyhow::{Result, bail};
use std::path::Path;

pub fn run(args: &VerifyArgs) -> Result<()> {
    let dir = paths::data_dir(args.paths.weiss.as_deref(), args.paths.data_dir.as_deref())?;
    let mut all_ok = true;
    for (label, fl_name, wi_name) in paths::targets(args.lang) {
        let fl = dir.join(fl_name);
        let wi = dir.join(wi_name);
        println!("\n[{label}] {}", fl.display());
        match verify_one(&fl, wi.is_file().then_some(wi.as_path())) {
            Ok(ok) => all_ok &= ok,
            Err(e) => {
                println!("  ERROR: {e:#}");
                all_ok = false;
            }
        }
    }
    if all_ok {
        println!("\nAll checks passed.");
        Ok(())
    } else {
        bail!("one or more checks failed")
    }
}

fn check(label: &str, cond: bool, ok: &mut bool) {
    println!("  {label:22} {}", if cond { "OK" } else { "FAIL" });
    *ok &= cond;
}

fn verify_one(fl_path: &Path, wi_path: Option<&Path>) -> Result<bool> {
    let enc = std::fs::read(fl_path)?;
    let dec = whitecrypt::decrypt_filelist(&enc)?;
    let fl = Filelist::parse(dec.clone())?;
    let mut ok = true;

    let body_size = whitecrypt::body_size(&dec)?;
    check("length", dec.len() == 32 + body_size + 8, &mut ok);
    check("body % 8", body_size % 8 == 0, &mut ok);

    let nblocks = (body_size - 8) / 4;
    let checksum: u32 = (0..nblocks)
        .map(|i| dec[32 + 4 * i] as u32)
        .fold(0u32, u32::wrapping_add);
    let stored = u32::from_le_bytes(dec[32 + body_size - 4..32 + body_size].try_into().unwrap());
    check("checksum", checksum == stored, &mut ok);

    let marker = u32::from_le_bytes(
        dec[32 + body_size - 8..32 + body_size - 4]
            .try_into()
            .unwrap(),
    );
    check("dataSize marker", marker as usize == body_size - 8, &mut ok);
    check("chunks", fl.num_chunks > 0 && fl.count > 0, &mut ok);

    let (ci_ok, off_ok, hi_ok) = strptr_invariants(&fl);
    check(
        &format!("strPtr chunk  {ci_ok}/{}", fl.count),
        ci_ok == fl.count,
        &mut ok,
    );
    check(
        &format!("strPtr offset {off_ok}/{}", fl.count),
        off_ok == fl.count,
        &mut ok,
    );
    check(
        &format!("strPtr odd-bit {hi_ok}/{}", fl.count),
        hi_ok == fl.count,
        &mut ok,
    );

    if let Some((n, info)) = fl.find_entry(inject::VIRTUAL_PATH) {
        println!("  imgb entry #{n}: {info}");
        if let Some(wi) = wi_path {
            let start = info.address_sector as u64 * SECTOR;
            let end = start + info.compressed_size as u64;
            check(
                "imgb in white_img",
                end <= std::fs::metadata(wi)?.len(),
                &mut ok,
            );
        }
    } else {
        println!("  imgb entry: (not found)");
    }

    Ok(ok)
}

/// (chunk index, in-chunk offset, high-bit) match counts over all entries.
fn strptr_invariants(fl: &Filelist) -> (usize, usize, usize) {
    let mut offs: Vec<(usize, usize)> = Vec::new();
    for (ci, chunk) in fl.chunks.iter().enumerate() {
        let mut pos = 0usize;
        for s in Filelist::chunk_strings(chunk) {
            offs.push((ci, pos));
            pos += s.len() + 1;
        }
    }

    let mut ci_ok = 0;
    let mut off_ok = 0;
    let mut hi_ok = 0;
    for (n, &(chunk, off)) in offs.iter().enumerate().take(fl.count) {
        let e = fl.entry(n);
        ci_ok += usize::from(e.chunk_index as usize == chunk / 2);
        off_ok += usize::from((e.string_pointer & 0x7FFF) as usize == off);
        hi_ok += usize::from(((e.string_pointer & 0x8000) != 0) == (chunk % 2 != 0));
    }
    (ci_ok, off_ok, hi_ok)
}
