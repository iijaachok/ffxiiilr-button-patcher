use crate::cli::PatchArgs;
use crate::{inject, paths};
use anyhow::{Context, Result, bail};

pub fn run(args: &PatchArgs) -> Result<()> {
    let (prompt, suffix) = if args.ps3 {
        ("ps3", "ps3")
    } else {
        ("xbox", "360")
    };
    let dir = paths::data_dir(args.paths.weiss.as_deref(), args.paths.data_dir.as_deref())?;
    let payload_path = paths::payload(args.payload.as_deref(), suffix, &dir)?;
    let payload = std::fs::read(&payload_path)
        .with_context(|| format!("reading payload {}", payload_path.display()))?;

    println!("Console Button Prompts patcher");
    println!("  data dir : {}", dir.display());
    println!(
        "  payload  : {} ({} bytes)",
        payload_path.display(),
        payload.len()
    );
    println!("  variant  : {prompt}");
    println!(
        "  backup   : {}",
        if args.no_backup {
            "disabled (--no-backup)"
        } else {
            "enabled (*.original)"
        }
    );
    if args.dry_run {
        println!("  mode     : DRY RUN (no files written)");
    }

    for (label, fl_name, wi_name) in paths::targets(args.lang) {
        let fl = dir.join(fl_name);
        let wi = dir.join(wi_name);
        if !fl.is_file() {
            bail!("missing {}", fl.display());
        }
        if !wi.is_file() {
            bail!("missing {}", wi.display());
        }

        println!("\n[{label}]");
        if !args.no_backup && !args.dry_run {
            inject::backup_once(&fl)?;
            inject::backup_once(&wi)?;
            println!("  backups written (*.original)");
        }

        let opts = inject::InjectOptions {
            filelist_path: fl,
            white_img_path: wi,
            payload: payload.clone(),
            dry_run: args.dry_run,
        };
        let r = inject::inject(&opts)?;
        println!("  entry #{:<5} -> {}", r.entry_index, r.new_info);
        println!("  was       : {}", r.old_info);
        println!(
            "  payload   : {raw} raw -> {stored} stored  (sector {sector})",
            raw = r.raw_size,
            stored = r.stored_size,
            sector = r.new_addr_sector
        );
        if !args.dry_run {
            println!(
                "  filelist  : {} bytes   white_img: {} bytes",
                r.new_filelist_size, r.new_white_img_size
            );
        }
    }

    if args.dry_run {
        println!("\nDry run complete.");
    } else {
        println!(
            "\nInstallation complete. In-game: Settings > On-Screen Button Explanations > \"Controller Type\"."
        );
    }
    Ok(())
}
