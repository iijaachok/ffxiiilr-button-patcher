// Fixed-width integer conversions in the filelist cipher.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

mod cli;
mod filelist;
mod inject;
mod patch;
mod paths;
mod restore;
mod verify;
mod whitecrypt;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Patch(a) => patch::run(&a),
        Command::Verify(a) => verify::run(&a),
        Command::Restore(a) => restore::run(&a),
    }
}
