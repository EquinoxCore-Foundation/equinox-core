#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::types::WriteBatch;
use crate::StorageError;

pub const WAL_MAGIC: [u8; 4] = *b"EQXW";
pub const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024; // 32 MiB hard limit per block batch

pub struct WalFile {
    path: PathBuf,
    file: File,
}

impl WalFile {
    /// Opens WAL, validates every frame via CRC32, and auto-truncates any partial power-cut tail.
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Vec<WriteBatch>, bool), StorageError> {
        let path_buf = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path_buf)?;

        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;

        let mut offset = 0usize;
        let mut batches = Vec::new();

        while offset + 12 <= raw.len() {
            if raw[offset..offset + 4] != WAL_MAGIC {
                break;
            }
            let len = u32::from_le_bytes([
                raw[offset + 4],
                raw[offset + 5],
                raw[offset + 6],
                raw[offset + 7],
            ]) as usize;
            let stored_crc = u32::from_le_bytes([
                raw[offset + 8],
                raw[offset + 9],
                raw[offset + 10],
                raw[offset + 11],
            ]);

            if len > MAX_FRAME_BYTES || offset + 12 + len > raw.len() {
                break;
            }
            let payload = &raw[offset + 12..offset + 12 + len];
            if crc32fast::hash(payload) != stored_crc {
                break;
            }
            match WriteBatch::decode(payload) {
                Ok(batch) => {
                    batches.push(batch);
                    offset += 12 + len;
                }
                Err(_) => break,
            }
        }

        let mut healed_corrupt_tail = false;
        if offset < raw.len() {
            file.set_len(offset as u64)?;
            file.sync_data()?;
            healed_corrupt_tail = true;
        }
        file.seek(SeekFrom::End(0))?;

        Ok((Self { path: path_buf, file }, batches, healed_corrupt_tail))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append_batch(&mut self, batch: &WriteBatch, sync_disk: bool) -> Result<(), StorageError> {
        let payload = batch.encode();
        if payload.len() > MAX_FRAME_BYTES {
            return Err(StorageError::FrameTooLarge);
        }
        let crc = crc32fast::hash(&payload);

        let mut frame = Vec::with_capacity(12 + payload.len());
        frame.extend_from_slice(&WAL_MAGIC);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.extend_from_slice(&payload);

        self.file.write_all(&frame)?;
        if sync_disk {
            self.file.sync_data()?;
        }
        Ok(())
    }
}
