use crate::cli::RestoreArgs;
use crate::{inject, paths};
use anyhow::Result;

pub fn run(args: &RestoreArgs) -> Result<()> {
    let dir = paths::data_dir(args.paths.weiss.as_deref(), args.paths.data_dir.as_deref())?;
    let mut restored = false;
    for (label, fl_name, wi_name) in paths::targets(crate::cli::Lang::All) {
        for name in [fl_name, wi_name] {
            let p = dir.join(name);
            if inject::restore(&p)? {
                println!("[{label}] restored {}", p.display());
                restored = true;
            }
        }
    }
    if !restored {
        println!("No `.original` backups found in {}.", dir.display());
    }
    Ok(())
}
