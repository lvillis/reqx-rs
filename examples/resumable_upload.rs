use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

#[cfg(feature = "_async")]
use reqx::prelude::{
    AsyncResumableUploadBackend, AsyncResumableUploader, ResumableUploadOptions, UploadedPart,
};
#[cfg(feature = "_async")]
use thiserror::Error;

#[cfg(feature = "_async")]
#[derive(Debug, Error)]
#[error("{message}")]
struct DemoError {
    message: String,
}

#[cfg(feature = "_async")]
#[derive(Default)]
struct DemoBackend {
    parts: Arc<Mutex<BTreeMap<u32, Vec<u8>>>>,
    fail_once_parts: Arc<Mutex<BTreeSet<u32>>>,
}

#[cfg(feature = "_async")]
impl DemoBackend {
    fn fail_once_for_part(&self, part_number: u32) {
        let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
        fail_once.insert(part_number);
    }
}

#[cfg(feature = "_async")]
impl AsyncResumableUploadBackend for DemoBackend {
    type Error = DemoError;

    async fn create_upload(&self) -> Result<String, Self::Error> {
        Ok("demo-upload-1".to_owned())
    }

    async fn upload_part(
        &self,
        _upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error> {
        let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
        if fail_once.remove(&part_number) {
            return Err(DemoError {
                message: format!("simulated transient failure on part {part_number}"),
            });
        }

        let mut parts = self.parts.lock().expect("lock parts");
        parts.insert(part_number, chunk.to_vec());
        Ok(UploadedPart {
            part_number,
            etag: format!("etag-{part_number}"),
            size: chunk.len(),
            checksum: None,
        })
    }

    async fn complete_upload(
        &self,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> Result<(), Self::Error> {
        println!("complete upload_id={upload_id} parts={}", parts.len());
        Ok(())
    }
}

#[cfg(feature = "_async")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let backend = DemoBackend::default();
    backend.fail_once_for_part(2);

    let first_attempt = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0),
    );
    let mut reader = Cursor::new(b"abcdefgh".to_vec());
    let failure = first_attempt
        .upload(&backend, &mut reader)
        .await
        .expect_err("first attempt should fail to demo checkpoint-based resume");
    let checkpoint = failure
        .into_checkpoint()
        .expect("part failure should include checkpoint");
    println!(
        "checkpoint persisted: upload_id={} completed_parts={}",
        checkpoint.upload_id,
        checkpoint.completed_parts.len()
    );

    let resumed = AsyncResumableUploader::new(
        ResumableUploadOptions::new()
            .with_part_size(4)
            .with_max_attempts(2)
            .with_jitter_ratio(0.0),
    );
    let mut replay_reader = Cursor::new(b"abcdefgh".to_vec());
    let result = resumed
        .resume(&backend, &mut replay_reader, checkpoint)
        .await?;
    println!(
        "resumed={} total_parts={} total_bytes={}",
        result.resumed, result.total_parts, result.total_bytes
    );
    Ok(())
}

#[cfg(not(feature = "_async"))]
fn main() {
    eprintln!("enable an `async-tls-*` feature to run this example");
}
