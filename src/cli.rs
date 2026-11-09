use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "lr13-btn-mod",
    version,
    about = "Console Button Prompts patcher for Lightning Returns: FFXIII"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Inject button-prompt textures into the game's archives
    Patch(PatchArgs),
    /// Decrypt and validate a filelist
    Verify(VerifyArgs),
    /// Restore the four game files from their .original backups
    Restore(RestoreArgs),
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
pub enum Lang {
    En,
    Jp,
    #[default]
    All,
}

#[derive(Args)]
pub struct PathOpts {
    #[arg(
        short = 'w',
        long,
        help = "weiss_data folder, or its sys/ directory (default: .)"
    )]
    pub weiss: Option<PathBuf>,
    /// Directory holding the four game files (default: sys)
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // ps3/xbox/no_backup/dry_run are CLI flags
#[command(group(ArgGroup::new("prompt").required(true).multiple(false).args(["ps3", "xbox"])))]
pub struct PatchArgs {
    #[command(flatten)]
    pub paths: PathOpts,
    #[arg(long, help = "Install PlayStation button prompts")]
    pub ps3: bool,
    #[arg(long, help = "Install Xbox button prompts")]
    pub xbox: bool,
    #[arg(long, help = "Payload imgb (default: mod/Misc/system.win32.<type>)")]
    pub payload: Option<PathBuf>,
    /// Filelists to patch
    #[arg(long, value_enum, default_value = "all")]
    pub lang: Lang,
    /// Skip the default *.original backups
    #[arg(long)]
    pub no_backup: bool,
    /// Do everything except writing files
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub paths: PathOpts,
    /// Filelists to check
    #[arg(long, value_enum, default_value = "all")]
    pub lang: Lang,
}

#[derive(Args)]
pub struct RestoreArgs {
    #[command(flatten)]
    pub paths: PathOpts,
}
