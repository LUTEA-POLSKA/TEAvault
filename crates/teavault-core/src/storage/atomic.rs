//! Durable writes.
//!
//! Two things must never happen: a half-written vault file surviving a crash,
//! and two processes writing the same file at once. Both are handled here
//! rather than at each call site.
//!
//! ## Atomicity
//!
//! Write to a temporary file in the *same directory* (a rename across
//! filesystems is not atomic), flush it to the device, then rename over the
//! target. A crash therefore leaves either the old complete file or the new
//! complete file, never a mixture.
//!
//! ## Locking
//!
//! A separate `vault.lock` file carries an exclusive advisory lock held for the
//! duration of a read-modify-write. It is separate from the data file so that
//! locking never requires the data file to exist, and so that replacing the
//! data file does not drop the lock.
//!
//! The lock is *advisory*: it stops two well-behaved TEAvault processes. It
//! cannot stop a process that ignores it, which is why the vault is also
//! authenticated — a second writer produces a file whose contents no longer
//! verify, and that is reported as `integrity` rather than silently accepted.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use fs2::FileExt;

use crate::error::{Error, Result};

/// Holds an exclusive lock on the vault for as long as it is alive.
pub struct VaultLock {
    _file: File,
}

impl VaultLock {
    /// Block until the lock is available.
    pub fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| Error::io("open vault lock", e))?;
        // Exclusive, blocking. The daemon holds this only around a
        // read-modify-write, never while idle, so contention is not a
        // background cost.
        file.lock_exclusive()
            .map_err(|e| Error::io("lock vault", e))?;
        Ok(Self { _file: file })
    }

    /// Try once, fail immediately if another process holds it.
    pub fn try_acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| Error::io("open vault lock", e))?;
        file.try_lock_exclusive()
            .map_err(|e| Error::io("lock vault", e))?;
        Ok(Self { _file: file })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // Releasing explicitly so the intent is visible; the OS would also drop
        // it on close.
        let _ = self._file.unlock();
    }
}

/// Replace `path` with `bytes`, atomically and durably.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        Error::io(
            "resolve parent directory",
            std::io::Error::other("no parent"),
        )
    })?;

    // Unique temporary name in the same directory, so a concurrent writer
    // cannot pick the same one.
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("vault"),
        std::process::id()
    ));

    // `create(true)` truncates an abandoned temporary from a previous crash.
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|e| Error::io("create temporary file", e))?;

    // Flush file contents to the device before the rename, so the rename
    // cannot publish a name that points at data still only in the page cache.
    let write = f.write_all(bytes).and_then(|_| f.sync_all());
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::io("write temporary file", e));
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::io("replace file", e));
    }

    Ok(())
}

/// Read a whole file, or `None` if it does not exist.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(mut f) => {
            let mut v = Vec::new();
            f.read_to_end(&mut v)
                .map_err(|e| Error::io("read file", e))?;
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io("read file", e)),
    }
}

/// Delete a file, ignoring "already gone".
pub fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io("remove file", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_leaves_no_temporary_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f.bin");
        write_atomic(&target, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file was not cleaned up");
    }

    #[test]
    fn a_second_write_replaces_rather_than_appends() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f.bin");
        write_atomic(&target, b"aaaaaaaa").unwrap();
        write_atomic(&target, b"bb").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"bb");
    }

    #[test]
    fn read_optional_distinguishes_missing_from_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_optional(&dir.path().join("nope")).unwrap(), None);
        let e = dir.path().join("empty");
        write_atomic(&e, b"").unwrap();
        assert_eq!(read_optional(&e).unwrap(), Some(vec![]));
    }

    #[test]
    fn the_lock_is_exclusive_within_a_process_too() {
        // Two handles in one process is enough to test the lock semantics
        // without spawning anything.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.lock");
        let _first = VaultLock::acquire(&path).unwrap();
        assert!(
            VaultLock::try_acquire(&path).is_err(),
            "a second writer must not be able to take the lock"
        );
    }

    #[test]
    fn the_lock_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.lock");
        {
            let _held = VaultLock::acquire(&path).unwrap();
        }
        assert!(
            VaultLock::try_acquire(&path).is_ok(),
            "dropping the guard must release the lock"
        );
    }
}
