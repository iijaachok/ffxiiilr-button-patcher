use crate::cli::Lang;
use anyhow::{Result, anyhow, bail};
use std::path::{Path, PathBuf};

pub fn targets(lang: Lang) -> Vec<(&'static str, &'static str, &'static str)> {
    let en = ("English", "filelist2a.win32.bin", "white_img2a.win32.bin");
    let jp = ("Japanese", "filelist2v.win32.bin", "white_img2v.win32.bin");
    match lang {
        Lang::En => vec![en],
        Lang::Jp => vec![jp],
        Lang::All => vec![en, jp],
    }
}

fn has_game_files(dir: &Path) -> bool {
    dir.join("filelist2a.win32.bin").exists() || dir.join("filelist2v.win32.bin").exists()
}

/// Directory holding the four game files. Defaults to `./sys` when run from the
/// `weiss_data` folder.
pub fn data_dir(weiss: Option<&Path>, data_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(d) = data_dir {
        if !d.is_dir() {
            bail!("--data-dir {} is not a directory", d.display());
        }
        return Ok(d.to_path_buf());
    }
    if let Some(w) = weiss {
        let sys = w.join("sys");
        if has_game_files(&sys) {
            return Ok(sys);
        }
        if !w.is_dir() {
            bail!("--weiss {} is not a directory", w.display());
        }
        return Ok(w.to_path_buf());
    }
    for cand in ["sys", "."] {
        let p = PathBuf::from(cand);
        if has_game_files(&p) {
            return Ok(p);
        }
    }
    bail!(
        "could not find the game files; run from the weiss_data folder, or pass --weiss <dir> / --data-dir <dir>"
    )
}

/// The payload imgb for the chosen variant. Defaults to `./mod/Misc/system.win32.<type>`.
pub fn payload(explicit: Option<&Path>, suffix: &str, data_dir: &Path) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.is_file() {
            bail!("--payload {} not found", p.display());
        }
        return Ok(p.to_path_buf());
    }
    let name = format!("system.win32.{suffix}");
    let mut candidates: Vec<PathBuf> = [
        PathBuf::from("mod/Misc"),
        PathBuf::from("mod/misc"),
        data_dir.join("../mod/Misc"),
        data_dir.join("../mod/misc"),
    ]
    .into_iter()
    .map(|d| d.join(&name))
    .collect();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("mod/Misc").join(&name));
        candidates.push(dir.join("mod/misc").join(&name));
    }
    candidates
        .into_iter()
        .find(|c| c.is_file())
        .ok_or_else(|| anyhow!("payload {name} not found; pass --payload <file>"))
}
