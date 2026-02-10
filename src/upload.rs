use std::collections::BTreeMap;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;

use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub const RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 2;
const LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 1;

fn legacy_checkpoint_version() -> u32 {
    LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartChecksumAlgorithm {
    Md5,
    Sha256,
}

impl PartChecksumAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha256 => "sha256",
        }
    }

    fn compute_hex(self, data: &[u8]) -> String {
        match self {
            Self::Md5 => format!("{:x}", md5::compute(data)),
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                encode_hex_lower(&hasher.finalize())
            }
        }
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadedPart {
    pub part_number: u32,
    pub etag: String,
    pub size: usize,
    #[serde(default)]
    pub checksum: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumableUploadCheckpoint {
    #[serde(default = "legacy_checkpoint_version")]
    pub version: u32,
    pub upload_id: String,
    pub part_size: usize,
    #[serde(default)]
    pub checksum_algorithm: Option<PartChecksumAlgorithm>,
    pub completed_parts: BTreeMap<u32, UploadedPart>,
}

impl ResumableUploadCheckpoint {
    pub fn new(upload_id: impl Into<String>, part_size: usize) -> Self {
        Self {
            version: RESUMABLE_UPLOAD_CHECKPOINT_VERSION,
            upload_id: upload_id.into(),
            part_size: part_size.max(1),
            checksum_algorithm: None,
            completed_parts: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumableUploadResult {
    pub upload_id: String,
    pub total_bytes: u64,
    pub total_parts: u32,
    pub resumed: bool,
    pub completed_parts: Vec<UploadedPart>,
}

#[derive(Clone, Debug)]
pub struct ResumableUploadOptions {
    part_size: usize,
    max_attempts: usize,
    base_backoff: Duration,
    max_backoff: Duration,
    jitter_ratio: f64,
    abort_on_error: bool,
    part_checksum_algorithm: Option<PartChecksumAlgorithm>,
    verify_remote_etag: bool,
}

impl ResumableUploadOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_part_size(mut self, part_size: usize) -> Self {
        self.part_size = part_size.max(1);
        self
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    pub fn with_base_backoff(mut self, base_backoff: Duration) -> Self {
        self.base_backoff = base_backoff.max(Duration::from_millis(1));
        if self.max_backoff < self.base_backoff {
            self.max_backoff = self.base_backoff;
        }
        self
    }

    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff.max(self.base_backoff);
        self
    }

    pub fn with_jitter_ratio(mut self, jitter_ratio: f64) -> Self {
        self.jitter_ratio = jitter_ratio.clamp(0.0, 1.0);
        self
    }

    pub fn with_abort_on_error(mut self, abort_on_error: bool) -> Self {
        self.abort_on_error = abort_on_error;
        self
    }

    pub fn with_part_checksum_algorithm(
        mut self,
        part_checksum_algorithm: PartChecksumAlgorithm,
    ) -> Self {
        self.part_checksum_algorithm = Some(part_checksum_algorithm);
        self
    }

    pub fn without_part_checksum_algorithm(mut self) -> Self {
        self.part_checksum_algorithm = None;
        self
    }

    pub fn with_verify_remote_etag(mut self, verify_remote_etag: bool) -> Self {
        self.verify_remote_etag = verify_remote_etag;
        self
    }

    pub fn part_size(&self) -> usize {
        self.part_size
    }

    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub fn part_checksum_algorithm(&self) -> Option<PartChecksumAlgorithm> {
        self.part_checksum_algorithm
    }

    pub fn verify_remote_etag(&self) -> bool {
        self.verify_remote_etag
    }

    fn backoff_for_retry(&self, retry_index: usize) -> Duration {
        let capped_exponent = retry_index.saturating_sub(1).min(31) as u32;
        let multiplier = 1_u128 << capped_exponent;
        let base_ms = self.base_backoff.as_millis().max(1);
        let max_ms = self.max_backoff.as_millis().max(base_ms);
        let delay_ms = base_ms
            .saturating_mul(multiplier)
            .min(max_ms)
            .min(u64::MAX as u128) as u64;
        self.apply_jitter(Duration::from_millis(delay_ms))
    }

    fn apply_jitter(&self, backoff: Duration) -> Duration {
        if self.jitter_ratio <= f64::EPSILON {
            return backoff;
        }

        let backoff_ms = backoff.as_millis().min(u64::MAX as u128) as u64;
        if backoff_ms <= 1 {
            return backoff;
        }

        let jitter_span = ((backoff_ms as f64) * self.jitter_ratio).round().max(1.0) as u64;
        let low = backoff_ms.saturating_sub(jitter_span);
        let high = backoff_ms.saturating_add(jitter_span).max(low);
        let mut rng = rand::rng();
        let sampled_ms = rng.random_range(low..=high);
        Duration::from_millis(sampled_ms)
    }

    fn expected_checksum(&self, chunk: &[u8]) -> Option<String> {
        self.part_checksum_algorithm
            .map(|algorithm| algorithm.compute_hex(chunk))
    }

    fn validate_uploaded_part<E>(
        &self,
        checkpoint: &ResumableUploadCheckpoint,
        part_number: u32,
        uploaded: &UploadedPart,
        expected_checksum: Option<&str>,
    ) -> Result<(), ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let Some(expected_checksum) = expected_checksum else {
            return Ok(());
        };

        if let Some(actual_checksum) = uploaded.checksum.as_deref() {
            let normalized_expected = normalize_token(expected_checksum);
            let normalized_actual = normalize_token(actual_checksum);
            if normalized_actual != normalized_expected {
                return Err(ResumableUploadError::PartChecksumMismatch {
                    part_number,
                    expected_checksum: normalized_expected,
                    actual_checksum: normalized_actual,
                    checkpoint: checkpoint.clone(),
                });
            }
        }

        if self.verify_remote_etag {
            let normalized_expected = normalize_token(expected_checksum);
            let normalized_actual = normalize_token(&uploaded.etag);
            if normalized_actual != normalized_expected {
                return Err(ResumableUploadError::PartEtagMismatch {
                    part_number,
                    expected_etag: normalized_expected,
                    actual_etag: normalized_actual,
                    checkpoint: checkpoint.clone(),
                });
            }
        }

        Ok(())
    }
}

impl Default for ResumableUploadOptions {
    fn default() -> Self {
        Self {
            part_size: 8 * 1024 * 1024,
            max_attempts: 3,
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
            jitter_ratio: 0.2,
            abort_on_error: false,
            part_checksum_algorithm: None,
            verify_remote_etag: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    #[error("failed to create resumable upload: {source}")]
    CreateFailed {
        #[source]
        source: E,
    },
    #[error(
        "checkpoint part size mismatch: checkpoint={checkpoint_part_size} options={options_part_size}"
    )]
    CheckpointPartSizeMismatch {
        checkpoint_part_size: usize,
        options_part_size: usize,
    },
    #[error(
        "checkpoint checksum algorithm mismatch: checkpoint={checkpoint_checksum_algorithm} options={options_checksum_algorithm}"
    )]
    CheckpointChecksumAlgorithmMismatch {
        checkpoint_checksum_algorithm: &'static str,
        options_checksum_algorithm: &'static str,
    },
    #[error(
        "unsupported checkpoint version {checkpoint_version}; max supported is {max_supported_version}"
    )]
    UnsupportedCheckpointVersion {
        checkpoint_version: u32,
        max_supported_version: u32,
    },
    #[error("checkpoint upload id is empty")]
    EmptyUploadId,
    #[error("source read failed")]
    SourceRead {
        #[source]
        source: std::io::Error,
        checkpoint: ResumableUploadCheckpoint,
    },
    #[error("upload part {part_number} failed after {attempts} attempts: {source}")]
    PartUploadFailed {
        part_number: u32,
        attempts: usize,
        checkpoint: ResumableUploadCheckpoint,
        #[source]
        source: E,
    },
    #[error(
        "upload part {part_number} checksum mismatch: expected={expected_checksum} actual={actual_checksum}"
    )]
    PartChecksumMismatch {
        part_number: u32,
        expected_checksum: String,
        actual_checksum: String,
        checkpoint: ResumableUploadCheckpoint,
    },
    #[error(
        "upload part {part_number} etag mismatch: expected={expected_etag} actual={actual_etag}"
    )]
    PartEtagMismatch {
        part_number: u32,
        expected_etag: String,
        actual_etag: String,
        checkpoint: ResumableUploadCheckpoint,
    },
    #[error("failed to complete resumable upload: {source}")]
    CompleteFailed {
        checkpoint: ResumableUploadCheckpoint,
        #[source]
        source: E,
    },
    #[error("upload body produced no parts")]
    EmptyUploadBody,
    #[error("missing completed metadata for part {part_number}")]
    MissingCompletedPart {
        part_number: u32,
        checkpoint: ResumableUploadCheckpoint,
    },
}

impl<E> ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    pub fn checkpoint(&self) -> Option<&ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::MissingCompletedPart { checkpoint, .. } => Some(checkpoint),
            _ => None,
        }
    }

    pub fn into_checkpoint(self) -> Option<ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::MissingCompletedPart { checkpoint, .. } => Some(checkpoint),
            _ => None,
        }
    }
}

pub trait BlockingResumableUploadBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    fn create_upload(&self) -> Result<String, Self::Error>;

    fn upload_part(
        &self,
        upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error>;

    fn complete_upload(&self, upload_id: &str, parts: &[UploadedPart]) -> Result<(), Self::Error>;

    fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(feature = "_async")]
#[allow(async_fn_in_trait)]
pub trait AsyncResumableUploadBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_upload(&self) -> Result<String, Self::Error>;

    async fn upload_part(
        &self,
        upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error>;

    async fn complete_upload(
        &self,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> Result<(), Self::Error>;

    async fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn normalize_part(mut part: UploadedPart, part_number: u32, expected_size: usize) -> UploadedPart {
    part.part_number = part_number;
    part.size = expected_size;
    part
}

fn checkpoint_supports_version(version: u32) -> bool {
    (LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION..=RESUMABLE_UPLOAD_CHECKPOINT_VERSION)
        .contains(&version)
}

fn validate_and_upgrade_checkpoint<E>(
    options: &ResumableUploadOptions,
    checkpoint: &mut ResumableUploadCheckpoint,
) -> Result<(), ResumableUploadError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    if !checkpoint_supports_version(checkpoint.version) {
        return Err(ResumableUploadError::UnsupportedCheckpointVersion {
            checkpoint_version: checkpoint.version,
            max_supported_version: RESUMABLE_UPLOAD_CHECKPOINT_VERSION,
        });
    }

    if checkpoint.part_size != options.part_size {
        return Err(ResumableUploadError::CheckpointPartSizeMismatch {
            checkpoint_part_size: checkpoint.part_size,
            options_part_size: options.part_size,
        });
    }

    if checkpoint.upload_id.trim().is_empty() {
        return Err(ResumableUploadError::EmptyUploadId);
    }

    match (
        checkpoint.checksum_algorithm,
        options.part_checksum_algorithm(),
    ) {
        (Some(checkpoint_algorithm), Some(options_algorithm))
            if checkpoint_algorithm != options_algorithm =>
        {
            return Err(ResumableUploadError::CheckpointChecksumAlgorithmMismatch {
                checkpoint_checksum_algorithm: checkpoint_algorithm.as_str(),
                options_checksum_algorithm: options_algorithm.as_str(),
            });
        }
        (None, Some(options_algorithm)) => {
            checkpoint.checksum_algorithm = Some(options_algorithm);
        }
        _ => {}
    }

    if checkpoint.version < RESUMABLE_UPLOAD_CHECKPOINT_VERSION {
        checkpoint.version = RESUMABLE_UPLOAD_CHECKPOINT_VERSION;
    }

    Ok(())
}

fn checkpoint_part_matches(
    existing: &UploadedPart,
    expected_size: usize,
    expected_checksum: Option<&str>,
) -> bool {
    if existing.size != expected_size {
        return false;
    }

    let Some(expected_checksum) = expected_checksum else {
        return true;
    };

    let Some(existing_checksum) = existing.checksum.as_deref() else {
        return false;
    };

    normalize_token(existing_checksum) == normalize_token(expected_checksum)
}

fn read_chunk<R>(reader: &mut R, part_size: usize) -> std::io::Result<Vec<u8>>
where
    R: Read,
{
    let mut buffer = vec![0_u8; part_size];
    let mut read_len = 0_usize;

    while read_len < part_size {
        let read = reader.read(&mut buffer[read_len..])?;
        if read == 0 {
            break;
        }
        read_len = read_len.saturating_add(read);
    }

    buffer.truncate(read_len);
    Ok(buffer)
}

pub struct BlockingResumableUploader {
    options: ResumableUploadOptions,
}

impl BlockingResumableUploader {
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }

    pub fn upload<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        let upload_id = backend
            .create_upload()
            .map_err(|source| ResumableUploadError::CreateFailed { source })?;
        let mut checkpoint = ResumableUploadCheckpoint::new(upload_id, self.options.part_size);
        checkpoint.checksum_algorithm = self.options.part_checksum_algorithm();
        self.upload_with_checkpoint(backend, reader, checkpoint, false)
    }

    pub fn resume<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        self.upload_with_checkpoint(backend, reader, checkpoint, true)
    }

    fn upload_with_checkpoint<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        mut checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        validate_and_upgrade_checkpoint::<B::Error>(&self.options, &mut checkpoint)?;

        let mut total_bytes = 0_u64;
        let mut part_number = 1_u32;

        loop {
            let chunk = read_chunk(reader, self.options.part_size).map_err(|source| {
                ResumableUploadError::SourceRead {
                    source,
                    checkpoint: checkpoint.clone(),
                }
            })?;
            if chunk.is_empty() {
                break;
            }
            total_bytes = total_bytes.saturating_add(chunk.len() as u64);

            let expected_checksum = self.options.expected_checksum(&chunk);
            if let Some(existing) = checkpoint.completed_parts.get(&part_number)
                && checkpoint_part_matches(existing, chunk.len(), expected_checksum.as_deref())
            {
                part_number = part_number.saturating_add(1);
                continue;
            }

            let mut attempt = 1_usize;
            let uploaded = loop {
                match backend.upload_part(&checkpoint.upload_id, part_number, &chunk) {
                    Ok(part) => {
                        let mut normalized = normalize_part(part, part_number, chunk.len());
                        if let Err(error) = self.options.validate_uploaded_part::<B::Error>(
                            &checkpoint,
                            part_number,
                            &normalized,
                            expected_checksum.as_deref(),
                        ) {
                            if self.options.abort_on_error {
                                let _ = backend.abort_upload(&checkpoint.upload_id);
                            }
                            return Err(error);
                        }
                        if normalized.checksum.is_none() {
                            normalized.checksum = expected_checksum.clone();
                        }
                        break normalized;
                    }
                    Err(source) => {
                        if attempt >= self.options.max_attempts {
                            if self.options.abort_on_error {
                                let _ = backend.abort_upload(&checkpoint.upload_id);
                            }
                            return Err(ResumableUploadError::PartUploadFailed {
                                part_number,
                                attempts: attempt,
                                checkpoint,
                                source,
                            });
                        }
                        let delay = self.options.backoff_for_retry(attempt);
                        if !delay.is_zero() {
                            sleep(delay);
                        }
                        attempt = attempt.saturating_add(1);
                    }
                }
            };

            checkpoint.completed_parts.insert(part_number, uploaded);
            part_number = part_number.saturating_add(1);
        }

        let total_parts = part_number.saturating_sub(1);
        if total_parts == 0 {
            return Err(ResumableUploadError::EmptyUploadBody);
        }

        let mut ordered_parts = Vec::with_capacity(total_parts as usize);
        for current in 1..=total_parts {
            let Some(part) = checkpoint.completed_parts.get(&current) else {
                return Err(ResumableUploadError::MissingCompletedPart {
                    part_number: current,
                    checkpoint,
                });
            };
            ordered_parts.push(part.clone());
        }

        if let Err(source) = backend.complete_upload(&checkpoint.upload_id, &ordered_parts) {
            return Err(ResumableUploadError::CompleteFailed { checkpoint, source });
        }

        let upload_id = checkpoint.upload_id.clone();

        Ok(ResumableUploadResult {
            upload_id,
            total_bytes,
            total_parts,
            resumed,
            completed_parts: ordered_parts,
        })
    }
}

impl Default for BlockingResumableUploader {
    fn default() -> Self {
        Self::new(ResumableUploadOptions::default())
    }
}

#[cfg(feature = "_async")]
pub struct AsyncResumableUploader {
    options: ResumableUploadOptions,
}

#[cfg(feature = "_async")]
impl AsyncResumableUploader {
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }

    pub async fn upload<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        let upload_id = backend
            .create_upload()
            .await
            .map_err(|source| ResumableUploadError::CreateFailed { source })?;
        let mut checkpoint = ResumableUploadCheckpoint::new(upload_id, self.options.part_size);
        checkpoint.checksum_algorithm = self.options.part_checksum_algorithm();
        self.upload_with_checkpoint(backend, reader, checkpoint, false)
            .await
    }

    pub async fn resume<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.upload_with_checkpoint(backend, reader, checkpoint, true)
            .await
    }

    async fn upload_with_checkpoint<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        mut checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;

        validate_and_upgrade_checkpoint::<B::Error>(&self.options, &mut checkpoint)?;

        let mut total_bytes = 0_u64;
        let mut part_number = 1_u32;

        loop {
            let mut chunk = vec![0_u8; self.options.part_size];
            let mut read_len = 0_usize;
            while read_len < self.options.part_size {
                let read = reader
                    .read(&mut chunk[read_len..])
                    .await
                    .map_err(|source| ResumableUploadError::SourceRead {
                        source,
                        checkpoint: checkpoint.clone(),
                    })?;
                if read == 0 {
                    break;
                }
                read_len = read_len.saturating_add(read);
            }
            chunk.truncate(read_len);

            if chunk.is_empty() {
                break;
            }
            total_bytes = total_bytes.saturating_add(chunk.len() as u64);

            let expected_checksum = self.options.expected_checksum(&chunk);
            if let Some(existing) = checkpoint.completed_parts.get(&part_number)
                && checkpoint_part_matches(existing, chunk.len(), expected_checksum.as_deref())
            {
                part_number = part_number.saturating_add(1);
                continue;
            }

            let mut attempt = 1_usize;
            let uploaded = loop {
                match backend
                    .upload_part(&checkpoint.upload_id, part_number, &chunk)
                    .await
                {
                    Ok(part) => {
                        let mut normalized = normalize_part(part, part_number, chunk.len());
                        if let Err(error) = self.options.validate_uploaded_part::<B::Error>(
                            &checkpoint,
                            part_number,
                            &normalized,
                            expected_checksum.as_deref(),
                        ) {
                            if self.options.abort_on_error {
                                let _ = backend.abort_upload(&checkpoint.upload_id).await;
                            }
                            return Err(error);
                        }
                        if normalized.checksum.is_none() {
                            normalized.checksum = expected_checksum.clone();
                        }
                        break normalized;
                    }
                    Err(source) => {
                        if attempt >= self.options.max_attempts {
                            if self.options.abort_on_error {
                                let _ = backend.abort_upload(&checkpoint.upload_id).await;
                            }
                            return Err(ResumableUploadError::PartUploadFailed {
                                part_number,
                                attempts: attempt,
                                checkpoint,
                                source,
                            });
                        }
                        let delay = self.options.backoff_for_retry(attempt);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        attempt = attempt.saturating_add(1);
                    }
                }
            };

            checkpoint.completed_parts.insert(part_number, uploaded);
            part_number = part_number.saturating_add(1);
        }

        let total_parts = part_number.saturating_sub(1);
        if total_parts == 0 {
            return Err(ResumableUploadError::EmptyUploadBody);
        }

        let mut ordered_parts = Vec::with_capacity(total_parts as usize);
        for current in 1..=total_parts {
            let Some(part) = checkpoint.completed_parts.get(&current) else {
                return Err(ResumableUploadError::MissingCompletedPart {
                    part_number: current,
                    checkpoint,
                });
            };
            ordered_parts.push(part.clone());
        }

        if let Err(source) = backend
            .complete_upload(&checkpoint.upload_id, &ordered_parts)
            .await
        {
            return Err(ResumableUploadError::CompleteFailed { checkpoint, source });
        }

        let upload_id = checkpoint.upload_id.clone();

        Ok(ResumableUploadResult {
            upload_id,
            total_bytes,
            total_parts,
            resumed,
            completed_parts: ordered_parts,
        })
    }
}

#[cfg(feature = "_async")]
impl Default for AsyncResumableUploader {
    fn default() -> Self {
        Self::new(ResumableUploadOptions::default())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    #[cfg(feature = "_async")]
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug, Error)]
    #[error("{message}")]
    struct MockError {
        message: String,
    }

    impl MockError {
        fn new(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
            }
        }
    }

    #[derive(Default)]
    struct BlockingMockBackend {
        uploaded_parts: Mutex<BTreeMap<u32, Vec<u8>>>,
        attempts: Mutex<BTreeMap<u32, usize>>,
        fail_once_parts: Mutex<BTreeSet<u32>>,
        etag_overrides: Mutex<BTreeMap<u32, String>>,
        checksum_overrides: Mutex<BTreeMap<u32, Option<String>>>,
        create_calls: AtomicUsize,
        completed: AtomicUsize,
    }

    impl BlockingMockBackend {
        fn fail_once_for_part(&self, part_number: u32) {
            let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
            fail_once.insert(part_number);
        }

        fn set_etag_for_part(&self, part_number: u32, etag: impl Into<String>) {
            let mut etag_overrides = self.etag_overrides.lock().expect("lock etag_overrides");
            etag_overrides.insert(part_number, etag.into());
        }

        fn set_checksum_for_part(&self, part_number: u32, checksum: Option<String>) {
            let mut checksum_overrides = self
                .checksum_overrides
                .lock()
                .expect("lock checksum_overrides");
            checksum_overrides.insert(part_number, checksum);
        }
    }

    impl BlockingResumableUploadBackend for BlockingMockBackend {
        type Error = MockError;

        fn create_upload(&self) -> Result<String, Self::Error> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            Ok("upload-1".to_owned())
        }

        fn upload_part(
            &self,
            _upload_id: &str,
            part_number: u32,
            chunk: &[u8],
        ) -> Result<UploadedPart, Self::Error> {
            let mut attempts = self.attempts.lock().expect("lock attempts");
            let attempt = attempts
                .entry(part_number)
                .and_modify(|value| *value = value.saturating_add(1))
                .or_insert(1_usize);
            let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
            if fail_once.remove(&part_number) {
                return Err(MockError::new(format!(
                    "part {part_number} failed on attempt {attempt}"
                )));
            }

            let mut uploaded = self.uploaded_parts.lock().expect("lock uploaded_parts");
            uploaded.insert(part_number, chunk.to_vec());

            let etag = self
                .etag_overrides
                .lock()
                .expect("lock etag_overrides")
                .get(&part_number)
                .cloned()
                .unwrap_or_else(|| PartChecksumAlgorithm::Md5.compute_hex(chunk));
            let checksum = self
                .checksum_overrides
                .lock()
                .expect("lock checksum_overrides")
                .get(&part_number)
                .cloned()
                .unwrap_or(None);

            Ok(UploadedPart {
                part_number,
                etag,
                size: chunk.len(),
                checksum,
            })
        }

        fn complete_upload(
            &self,
            _upload_id: &str,
            _parts: &[UploadedPart],
        ) -> Result<(), Self::Error> {
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn checkpoint_deserializes_legacy_payload_without_version() {
        let payload = r#"{
            "upload_id":"upload-legacy",
            "part_size":4,
            "completed_parts":{
                "1":{"part_number":1,"etag":"etag-1","size":4}
            }
        }"#;

        let checkpoint: ResumableUploadCheckpoint =
            serde_json::from_str(payload).expect("legacy checkpoint should deserialize");

        assert_eq!(
            checkpoint.version,
            LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION
        );
        assert_eq!(checkpoint.checksum_algorithm, None);
        assert_eq!(
            checkpoint
                .completed_parts
                .get(&1)
                .and_then(|item| item.checksum.as_deref()),
            None
        );
    }

    #[test]
    fn blocking_resume_skips_already_completed_parts() {
        let backend = BlockingMockBackend::default();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
        checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
        checkpoint.completed_parts.insert(
            1,
            UploadedPart {
                part_number: 1,
                etag: "etag-1".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let result = uploader
            .resume(&backend, &mut reader, checkpoint)
            .expect("resume should succeed");

        assert!(result.resumed);
        assert_eq!(result.total_parts, 2);
        assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            backend
                .attempts
                .lock()
                .expect("lock attempts")
                .get(&1)
                .copied(),
            None
        );
        assert_eq!(
            backend
                .attempts
                .lock()
                .expect("lock attempts")
                .get(&2)
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn blocking_retry_failure_returns_checkpoint_for_resume() {
        let backend = BlockingMockBackend::default();
        backend.fail_once_for_part(2);
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(1)
                .with_base_backoff(Duration::from_millis(1))
                .with_max_backoff(Duration::from_millis(1))
                .with_jitter_ratio(0.0),
        );

        let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("upload should fail when retries exhausted");

        match error {
            ResumableUploadError::PartUploadFailed {
                part_number,
                attempts,
                checkpoint,
                ..
            } => {
                assert_eq!(part_number, 2);
                assert_eq!(attempts, 1);
                let part_1 = checkpoint
                    .completed_parts
                    .get(&1)
                    .expect("part 1 should be in checkpoint");
                assert_eq!(
                    part_1.checksum.as_deref(),
                    Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd").as_str())
                );
                assert!(!checkpoint.completed_parts.contains_key(&2));
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn blocking_etag_mismatch_returns_integrity_error() {
        let backend = BlockingMockBackend::default();
        backend.set_etag_for_part(1, "not-md5");
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_verify_remote_etag(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("upload should fail on etag mismatch");

        match error {
            ResumableUploadError::PartEtagMismatch {
                part_number,
                checkpoint,
                ..
            } => {
                assert_eq!(part_number, 1);
                assert!(checkpoint.completed_parts.is_empty());
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn blocking_checkpoint_checksum_algorithm_mismatch_is_rejected() {
        let backend = BlockingMockBackend::default();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Sha256)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
        checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .resume(&backend, &mut reader, checkpoint)
            .expect_err("resume should reject checksum algorithm mismatch");

        match error {
            ResumableUploadError::CheckpointChecksumAlgorithmMismatch { .. } => {}
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn blocking_part_checksum_mismatch_returns_integrity_error() {
        let backend = BlockingMockBackend::default();
        backend.set_checksum_for_part(1, Some("bad-checksum".to_owned()));
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("upload should fail on checksum mismatch");

        match error {
            ResumableUploadError::PartChecksumMismatch {
                part_number,
                checkpoint,
                ..
            } => {
                assert_eq!(part_number, 1);
                assert!(checkpoint.completed_parts.is_empty());
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[cfg(feature = "_async")]
    #[derive(Default)]
    struct AsyncMockBackend {
        uploaded_parts: Arc<Mutex<BTreeMap<u32, Vec<u8>>>>,
        attempts: Arc<Mutex<BTreeMap<u32, usize>>>,
        fail_once_parts: Arc<Mutex<BTreeSet<u32>>>,
        create_calls: Arc<AtomicUsize>,
        completed: Arc<AtomicUsize>,
    }

    #[cfg(feature = "_async")]
    impl AsyncMockBackend {
        fn fail_once_for_part(&self, part_number: u32) {
            let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
            fail_once.insert(part_number);
        }
    }

    #[cfg(feature = "_async")]
    impl AsyncResumableUploadBackend for AsyncMockBackend {
        type Error = MockError;

        async fn create_upload(&self) -> Result<String, Self::Error> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            Ok("upload-async-1".to_owned())
        }

        async fn upload_part(
            &self,
            _upload_id: &str,
            part_number: u32,
            chunk: &[u8],
        ) -> Result<UploadedPart, Self::Error> {
            let mut attempts = self.attempts.lock().expect("lock attempts");
            let attempt = attempts
                .entry(part_number)
                .and_modify(|value| *value = value.saturating_add(1))
                .or_insert(1_usize);
            let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
            if fail_once.remove(&part_number) {
                return Err(MockError::new(format!(
                    "part {part_number} failed on attempt {attempt}"
                )));
            }

            let mut uploaded = self.uploaded_parts.lock().expect("lock uploaded_parts");
            uploaded.insert(part_number, chunk.to_vec());
            Ok(UploadedPart {
                part_number,
                etag: PartChecksumAlgorithm::Md5.compute_hex(chunk),
                size: chunk.len(),
                checksum: None,
            })
        }

        async fn complete_upload(
            &self,
            _upload_id: &str,
            _parts: &[UploadedPart],
        ) -> Result<(), Self::Error> {
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[cfg(feature = "_async")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_resume_reuses_checkpoint_and_completes() {
        let backend = AsyncMockBackend::default();
        backend.fail_once_for_part(2);
        let uploader = AsyncResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(1)
                .with_base_backoff(Duration::from_millis(1))
                .with_max_backoff(Duration::from_millis(1))
                .with_jitter_ratio(0.0),
        );

        let mut first_reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let first_error = uploader
            .upload(&backend, &mut first_reader)
            .await
            .expect_err("first upload should fail");
        let checkpoint = first_error
            .into_checkpoint()
            .expect("checkpoint should be attached");
        let part_1 = checkpoint
            .completed_parts
            .get(&1)
            .expect("part 1 should be uploaded before failure");
        assert!(part_1.checksum.is_some());

        let mut second_reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let resumed = AsyncResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(2)
                .with_base_backoff(Duration::from_millis(1))
                .with_max_backoff(Duration::from_millis(1))
                .with_jitter_ratio(0.0),
        )
        .resume(&backend, &mut second_reader, checkpoint)
        .await
        .expect("resume should succeed");

        assert!(resumed.resumed);
        assert_eq!(resumed.total_parts, 2);
        assert_eq!(backend.completed.load(Ordering::SeqCst), 1);
    }
}
