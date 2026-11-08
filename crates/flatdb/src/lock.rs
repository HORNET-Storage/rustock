//! An exclusive lock on a database directory.
//!
//! Two processes mapping the same heap would each believe they owned the
//! write frontier. It is also the soundness argument for every `unsafe`
//! mapping in this crate: no cooperating process truncates or rewrites a
//! file while it is mapped. The lock is `File::try_lock`: `flock` on Unix,
//! `LockFileEx` on Windows. Either is released by the system when the
//! process dies, so a crash does not leave the directory unopenable.

use std::fs::File;
use std::io;
use std::path::Path;

pub struct DbLock {
    _file: File,
}

impl DbLock {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("database is already open: {}", path.display()),
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_acquisition_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock.dat");
        let _held = DbLock::acquire(&path).unwrap();
        let error = DbLock::acquire(&path).err().expect("the second must be refused");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn releasing_lets_the_next_one_in() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock.dat");
        drop(DbLock::acquire(&path).unwrap());
        DbLock::acquire(&path).expect("the lock was released");
    }
}
