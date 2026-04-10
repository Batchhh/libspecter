//! Standalone memory backup and restore
//!
//! Backs up a memory region independently of the patching system,
//! allowing restoration of original bytes at any time.

use crate::memory::manipulation::patch::stealth_write;
use crate::memory::platform::thread;
#[cfg(debug_assertions)]
use crate::utils::logger;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error("Read failed at {0:#x}")]
    ReadFailed(usize),
    #[error("Restore failed: {0}")]
    RestoreFailed(String),
    #[error("Thread error: {0}")]
    ThreadError(#[from] thread::ThreadError),
}

pub struct MemoryBackup {
    address: usize,
    original_bytes: Vec<u8>,
}

impl MemoryBackup {
    /// Create a backup of `size` bytes starting at `address`
    pub fn create(address: usize, size: usize) -> Result<Self, BackupError> {
        let original_bytes = unsafe { read_bytes(address, size) };

        #[cfg(debug_assertions)]
        logger::debug(&format!("Backup created: {:#x} ({} bytes)", address, size));

        Ok(Self {
            address,
            original_bytes,
        })
    }

    /// Restore the original bytes back to memory
    pub fn restore(&self) -> Result<(), BackupError> {
        unsafe {
            let suspended = thread::suspend_other_threads()?;

            if let Err(e) = stealth_write(self.address, &self.original_bytes) {
                thread::resume_threads(&suspended);
                return Err(BackupError::RestoreFailed(e.to_string()));
            }

            thread::resume_threads(&suspended);

            #[cfg(debug_assertions)]
            logger::debug(&format!("Backup restored: {:#x}", self.address));
        }
        Ok(())
    }

    pub fn address(&self) -> usize {
        self.address
    }

    pub fn size(&self) -> usize {
        self.original_bytes.len()
    }

    pub fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    /// Read the current bytes at the backed-up address
    pub fn current_bytes(&self) -> Vec<u8> {
        unsafe { read_bytes(self.address, self.original_bytes.len()) }
    }
}

unsafe fn read_bytes(address: usize, len: usize) -> Vec<u8> {
    unsafe {
        (0..len)
            .map(|i| crate::memory::manipulation::rw::read::<u8>(address + i).unwrap_or(0))
            .collect()
    }
}
