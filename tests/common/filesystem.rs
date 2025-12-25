//! Filesystem helpers for test file I/O operations

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncReadExt;

/// Write content to a file
///
/// Creates parent directories if they don't exist
pub async fn write_file(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create parent directories for {:?}", path))?;
    }

    fs::write(path, content)
        .await
        .with_context(|| format!("Failed to write to {:?}", path))
}

/// Read content from a file
pub async fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path)
        .await
        .with_context(|| format!("Failed to read from {:?}", path))
}

/// Verify file content matches expected bytes
pub async fn verify_file_content(path: &Path, expected: &[u8]) -> Result<()> {
    let actual = read_file(path).await?;

    if actual != expected {
        anyhow::bail!(
            "File content mismatch at {:?}. Expected {} bytes, got {} bytes",
            path,
            expected.len(),
            actual.len()
        );
    }

    Ok(())
}

/// Check if a path is accessible (exists and readable)
pub async fn is_accessible(path: &Path) -> bool {
    fs::metadata(path).await.is_ok()
}

/// Generate random test data of specified size
///
/// Uses predictable pattern for reproducibility while avoiding compression
pub fn random_test_data(size: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut data = Vec::with_capacity(size);
    let mut hasher = DefaultHasher::new();

    for i in 0..size {
        i.hash(&mut hasher);
        let byte = (hasher.finish() & 0xFF) as u8;
        data.push(byte);
    }

    data
}

/// Calculate SHA256 checksum of a file
///
/// Useful for verifying large file transfers
pub async fn calculate_checksum(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut file = fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open {:?} for checksum", path))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = file
            .read(&mut buffer)
            .await
            .context("Failed to read file for checksum")?;

        if n == 0 {
            break;
        }

        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Compare two files for equality
pub async fn files_equal(path1: &Path, path2: &Path) -> Result<bool> {
    let content1 = read_file(path1).await?;
    let content2 = read_file(path2).await?;

    Ok(content1 == content2)
}

/// Check if a file exists
pub async fn file_exists(path: &Path) -> bool {
    fs::metadata(path).await.is_ok()
}

/// Get file size in bytes
pub async fn file_size(path: &Path) -> Result<u64> {
    let metadata = fs::metadata(path)
        .await
        .with_context(|| format!("Failed to get metadata for {:?}", path))?;

    Ok(metadata.len())
}

/// List files in a directory
pub async fn list_files(dir: &Path) -> Result<Vec<String>> {
    let mut entries = fs::read_dir(dir)
        .await
        .with_context(|| format!("Failed to read directory {:?}", dir))?;

    let mut files = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        if let Ok(name) = entry.file_name().into_string() {
            files.push(name);
        }
    }

    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_write_and_read_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test.txt");

        let content = b"Hello, World!";
        write_file(&file_path, content).await?;

        let read_content = read_file(&file_path).await?;
        assert_eq!(content, &read_content[..]);

        Ok(())
    }

    #[tokio::test]
    async fn test_verify_file_content() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test.txt");

        let content = b"Test content";
        write_file(&file_path, content).await?;

        verify_file_content(&file_path, content).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_random_test_data() {
        let data1 = random_test_data(1024);
        let data2 = random_test_data(1024);

        assert_eq!(data1.len(), 1024);
        assert_eq!(data2.len(), 1024);
        // Should be deterministic
        assert_eq!(data1, data2);
    }

    #[tokio::test]
    async fn test_calculate_checksum() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test.bin");

        let content = b"Test content for checksum";
        write_file(&file_path, content).await?;

        let checksum1 = calculate_checksum(&file_path).await?;
        let checksum2 = calculate_checksum(&file_path).await?;

        assert_eq!(checksum1, checksum2);
        assert_eq!(checksum1.len(), 64); // SHA256 hex string length

        Ok(())
    }

    #[tokio::test]
    async fn test_files_equal() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let file3 = temp_dir.path().join("file3.txt");

        write_file(&file1, b"same content").await?;
        write_file(&file2, b"same content").await?;
        write_file(&file3, b"different").await?;

        assert!(files_equal(&file1, &file2).await?);
        assert!(!files_equal(&file1, &file3).await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_is_accessible() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let existing_file = temp_dir.path().join("exists.txt");
        let missing_file = temp_dir.path().join("missing.txt");

        write_file(&existing_file, b"content").await?;

        assert!(is_accessible(&existing_file).await);
        assert!(!is_accessible(&missing_file).await);

        Ok(())
    }

    #[tokio::test]
    async fn test_list_files() -> Result<()> {
        let temp_dir = TempDir::new()?;

        write_file(&temp_dir.path().join("file1.txt"), b"1").await?;
        write_file(&temp_dir.path().join("file2.txt"), b"2").await?;
        write_file(&temp_dir.path().join("file3.txt"), b"3").await?;

        let files = list_files(temp_dir.path()).await?;

        assert_eq!(files, vec!["file1.txt", "file2.txt", "file3.txt"]);

        Ok(())
    }
}
