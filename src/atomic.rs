//! Shared "write .tmp, fsync, [chmod,] rename()" helper. The Go source
//! hand-rolls this exact dance three separate times (`publish/hosts.go`'s
//! `atomicWrite`, `engine/state.go`'s `saveStateLocked`, `status/status.go`'s
//! `Write`) with byte-identical logic apart from the temp-file prefix and
//! whether a chmod(0644) is applied afterward. Consolidated into one
//! function here -- a safe simplification, not a behavior change: each
//! caller still gets exactly the semantics its Go counterpart had,
//! including the one deliberate asymmetry (hosts.go chmods 0644;
//! state.json/status.json do not, inheriting the temp file's default
//! permissions) which callers select explicitly via `mode`.
//!
//! On any failure the partially-written temp file is removed (mirroring
//! Go's `os.Remove` cleanup / `defer os.Remove(tmpName)` safety net) --
//! `tempfile::NamedTempFile`'s `Drop` impl does this automatically for us
//! whenever the file is not persisted.

use std::io::{self, Write};
use std::path::Path;

/// Writes `data` to `target` atomically, applying `mode` (e.g. `0o644`) to
/// the temp file before the rename.
pub fn write_with_chmod(
    dir: &Path,
    target: &Path,
    data: &[u8],
    prefix: &str,
    mode: u32,
) -> io::Result<()> {
    write_impl(dir, target, data, prefix, Some(mode))
}

/// Writes `data` to `target` atomically, with no explicit chmod -- the
/// published file inherits whatever permissions `tempfile` gives a fresh
/// temp file (0600), exactly like Go's bare `os.CreateTemp` result.
pub fn write_no_chmod(dir: &Path, target: &Path, data: &[u8], prefix: &str) -> io::Result<()> {
    write_impl(dir, target, data, prefix, None)
}

fn write_impl(
    dir: &Path,
    target: &Path,
    data: &[u8],
    prefix: &str,
    mode: Option<u32>,
) -> io::Result<()> {
    let mut tmp = tempfile::Builder::new().prefix(prefix).tempfile_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }
    tmp.persist(target).map_err(|e| e.error)?;
    Ok(())
}
