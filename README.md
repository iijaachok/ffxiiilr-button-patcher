# lr13-btn-mod

Installs the Console Button Prompts mod for _Lightning Returns: Final Fantasy XIII_,
replacing the mod's Windows batch installer. Filelist encryption and decryption are
ported from [WhiteCryptTool](https://github.com/Surihix/WhiteCryptTool).

Based on mod that can be discovered by searching for `FFXIII-LR - Console Button Prompts (v1.0).7z`. This is a Rust cross-platform CLI binary for other platforms other than Windows.

## Build

```sh
cargo build --release
```

## Setup

Copy the binary and the `mod/` folder from the original patch into the game's
`weiss_data` folder (containing `sys/`):

```text
weiss_data/
  lr13-btn-mod
  sys/
    filelist2a.win32.bin
    white_img2a.win32.bin
    filelist2v.win32.bin
    white_img2v.win32.bin
  mod/
    Misc/
      system.win32.ps3
      system.win32.360
```

## Usage

Run the binary from the `weiss_data` folder:

```sh
lr13-btn-mod patch --ps3
lr13-btn-mod patch --xbox
lr13-btn-mod verify
lr13-btn-mod restore
```

Options:

```text
--weiss <DIR>        weiss_data folder, or its sys/ directory (default: .)
--data-dir <DIR>     directory holding the four game files (default: sys)
--payload <FILE>     payload imgb (default: mod/Misc/system.win32.<type>)
--lang en|jp|all     filelists to patch (default: all)
--no-backup          skip the *.original backups
--dry-run            preview only
```

`patch` edits the files in place. In game, set
**Settings > On-Screen Button Explanations > Controller Type**.

## License

GPL-3.0-or-later.
