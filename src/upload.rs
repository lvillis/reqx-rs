use std::collections::BTreeMap;
#[cfg(feature = "_async")]
use std::future::Future;
use std::io::{self, Read};
use std::thread::sleep;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "_async")]
use crate::util::read_async_retry_interrupted;
use crate::util::{exponential_backoff_with_jitter, read_retry_interrupted};

/// Current resumable upload checkpoint schema version.
pub const RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 2;
const LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION: u32 = 1;
const MAX_RESUMABLE_UPLOAD_PART_NUMBER: u32 = u32::MAX;

fn legacy_checkpoint_version() -> u32 {
    LEGACY_RESUMABLE_UPLOAD_CHECKPOINT_VERSION
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Checksum algorithm used for uploaded parts.
pub enum PartChecksumAlgorithm {
    /// MD5 checksum in lowercase hex form.
    Md5,
    /// SHA-256 checksum in lowercase hex form.
    Sha256,
}

impl PartChecksumAlgorithm {
    /// Returns the stable string identifier for this checksum algorithm.
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
/// Metadata recorded for one successfully uploaded part.
pub struct UploadedPart {
    /// One-based part number.
    pub part_number: u32,
    /// Remote ETag returned by the upload backend.
    pub etag: String,
    /// Number of bytes uploaded for this part.
    pub size: usize,
    #[serde(default)]
    /// Optional checksum recorded for this part.
    pub checksum: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Serializable checkpoint used to resume multipart uploads.
pub struct ResumableUploadCheckpoint {
    #[serde(default = "legacy_checkpoint_version")]
    /// Checkpoint schema version.
    pub version: u32,
    /// Backend upload identifier.
    pub upload_id: String,
    /// Fixed part size used for this upload.
    pub part_size: usize,
    #[serde(default)]
    /// Optional checksum algorithm used for uploaded parts.
    pub checksum_algorithm: Option<PartChecksumAlgorithm>,
    /// Completed parts keyed by part number.
    pub completed_parts: BTreeMap<u32, UploadedPart>,
}

impl ResumableUploadCheckpoint {
    /// Creates an empty checkpoint for a new upload.
    pub fn new(upload_id: impl Into<String>, part_size: usize) -> Self {
        Self {
            version: RESUMABLE_UPLOAD_CHECKPOINT_VERSION,
            upload_id: upload_id.into(),
            part_size,
            checksum_algorithm: None,
            completed_parts: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Summary returned after a resumable upload completes.
pub struct ResumableUploadResult {
    /// Backend upload identifier.
    pub upload_id: String,
    /// Total number of uploaded bytes.
    pub total_bytes: u64,
    /// Total number of uploaded parts.
    pub total_parts: u32,
    /// Whether the upload resumed from an existing checkpoint.
    pub resumed: bool,
    /// Completed parts in order.
    pub completed_parts: Vec<UploadedPart>,
}

#[derive(Clone, Debug)]
/// Options controlling resumable upload chunking, retries, and verification.
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
    /// Creates options with the default resumable upload settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the size of each uploaded part in bytes.
    pub fn with_part_size(mut self, part_size: usize) -> Self {
        self.part_size = part_size;
        self
    }

    /// Sets how many attempts are allowed for each part upload.
    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Sets the base retry backoff used between part upload attempts.
    pub fn with_base_backoff(mut self, base_backoff: Duration) -> Self {
        self.base_backoff = base_backoff;
        self
    }

    /// Sets the maximum retry backoff used between part upload attempts.
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Sets the backoff jitter ratio applied to retry delays.
    pub fn with_jitter_ratio(mut self, jitter_ratio: f64) -> Self {
        self.jitter_ratio = jitter_ratio;
        self
    }

    /// Aborts the remote upload when a terminal error is encountered.
    pub fn with_abort_on_error(mut self, abort_on_error: bool) -> Self {
        self.abort_on_error = abort_on_error;
        self
    }

    /// Enables checksum verification for uploaded parts.
    pub fn with_part_checksum_algorithm(
        mut self,
        part_checksum_algorithm: PartChecksumAlgorithm,
    ) -> Self {
        self.part_checksum_algorithm = Some(part_checksum_algorithm);
        self
    }

    /// Disables checksum generation and verification for uploaded parts.
    pub fn without_part_checksum_algorithm(mut self) -> Self {
        self.part_checksum_algorithm = None;
        self
    }

    /// Verifies that the remote ETag matches the computed checksum.
    ///
    /// Enabling this requires a part checksum algorithm.
    pub fn with_verify_remote_etag(mut self, verify_remote_etag: bool) -> Self {
        self.verify_remote_etag = verify_remote_etag;
        self
    }

    /// Returns the configured part size in bytes.
    pub fn part_size(&self) -> usize {
        self.part_size
    }

    /// Returns the configured maximum attempts per part.
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    /// Returns the configured part checksum algorithm, if any.
    pub fn part_checksum_algorithm(&self) -> Option<PartChecksumAlgorithm> {
        self.part_checksum_algorithm
    }

    /// Returns whether remote ETags are checked against the expected checksum.
    pub fn verify_remote_etag(&self) -> bool {
        self.verify_remote_etag
    }

    fn backoff_for_retry(&self, retry_index: usize) -> Duration {
        exponential_backoff_with_jitter(
            retry_index,
            self.base_backoff,
            self.max_backoff,
            self.jitter_ratio,
        )
    }

    fn validate<E>(&self) -> Result<(), ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if self.part_size == 0 {
            return Err(self.invalid_options("part_size must be greater than zero"));
        }
        if self.max_attempts == 0 {
            return Err(self.invalid_options("max_attempts must be greater than zero"));
        }
        if self.base_backoff.is_zero() {
            return Err(self.invalid_options("base_backoff must be greater than zero"));
        }
        if self.max_backoff.is_zero() {
            return Err(self.invalid_options("max_backoff must be greater than zero"));
        }
        if self.max_backoff < self.base_backoff {
            return Err(
                self.invalid_options("max_backoff must be greater than or equal to base_backoff")
            );
        }
        if !self.jitter_ratio.is_finite() || !(0.0..=1.0).contains(&self.jitter_ratio) {
            return Err(self.invalid_options("jitter_ratio must be finite and between 0.0 and 1.0"));
        }
        if self.verify_remote_etag && self.part_checksum_algorithm.is_none() {
            return Err(self.invalid_options("verify_remote_etag requires part_checksum_algorithm"));
        }
        Ok(())
    }

    fn invalid_options<E>(&self, message: &'static str) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::InvalidOptions {
            part_size: self.part_size,
            max_attempts: self.max_attempts,
            base_backoff_ms: self.base_backoff.as_millis(),
            max_backoff_ms: self.max_backoff.as_millis(),
            jitter_ratio: self.jitter_ratio,
            message,
        }
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
/// Error returned by a resumable upload operation.
pub enum ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Resumable upload options were invalid.
    #[error(
        "invalid resumable upload options (part_size={part_size}, max_attempts={max_attempts}, base_backoff_ms={base_backoff_ms}, max_backoff_ms={max_backoff_ms}, jitter_ratio={jitter_ratio}): {message}"
    )]
    InvalidOptions {
        /// Configured part size.
        part_size: usize,
        /// Configured attempts per part.
        max_attempts: usize,
        /// Configured base backoff in milliseconds.
        base_backoff_ms: u128,
        /// Configured maximum backoff in milliseconds.
        max_backoff_ms: u128,
        /// Configured jitter ratio.
        jitter_ratio: f64,
        /// Validation failure explanation.
        message: &'static str,
    },
    /// Creating the remote upload session failed.
    #[error("failed to create resumable upload: {source}")]
    CreateFailed {
        #[source]
        /// Source error returned by the backend.
        source: E,
    },
    /// The checkpoint part size did not match the active options.
    #[error(
        "checkpoint part size mismatch: checkpoint={checkpoint_part_size} options={options_part_size}"
    )]
    CheckpointPartSizeMismatch {
        /// Part size stored in the checkpoint.
        checkpoint_part_size: usize,
        /// Part size configured in the active options.
        options_part_size: usize,
    },
    /// The checkpoint checksum algorithm did not match the active options.
    #[error(
        "checkpoint checksum algorithm mismatch: checkpoint={checkpoint_checksum_algorithm} options={options_checksum_algorithm}"
    )]
    CheckpointChecksumAlgorithmMismatch {
        /// Checksum algorithm stored in the checkpoint.
        checkpoint_checksum_algorithm: &'static str,
        /// Checksum algorithm configured in the active options.
        options_checksum_algorithm: &'static str,
    },
    /// The checkpoint version was newer than this crate understands.
    #[error(
        "unsupported checkpoint version {checkpoint_version}; max supported is {max_supported_version}"
    )]
    UnsupportedCheckpointVersion {
        /// Version stored in the checkpoint.
        checkpoint_version: u32,
        /// Highest checkpoint version supported by this crate.
        max_supported_version: u32,
    },
    /// The checkpoint upload id was empty.
    #[error("checkpoint upload id is empty")]
    EmptyUploadId,
    /// Reading the source stream failed.
    #[error("source read failed")]
    SourceRead {
        #[source]
        /// Source I/O error.
        source: std::io::Error,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// Uploading a part failed after exhausting retries.
    #[error("upload part {part_number} failed after {attempts} attempts: {source}")]
    PartUploadFailed {
        /// One-based part number.
        part_number: u32,
        /// Number of attempts that were made.
        attempts: usize,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
        #[source]
        /// Source error returned by the backend.
        source: E,
    },
    /// The backend returned metadata for a different part number.
    #[error("upload part {expected_part_number} returned metadata for part {actual_part_number}")]
    PartNumberMismatch {
        /// Expected one-based part number.
        expected_part_number: u32,
        /// Backend-reported one-based part number.
        actual_part_number: u32,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// The backend returned a byte size that did not match the uploaded chunk.
    #[error(
        "upload part {part_number} returned size {actual_size} but uploaded {expected_size} bytes"
    )]
    PartSizeMismatch {
        /// One-based part number.
        part_number: u32,
        /// Expected uploaded byte count.
        expected_size: usize,
        /// Backend-reported byte count.
        actual_size: usize,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// A backend-reported checksum did not match the expected checksum.
    #[error(
        "upload part {part_number} checksum mismatch: expected={expected_checksum} actual={actual_checksum}"
    )]
    PartChecksumMismatch {
        /// One-based part number.
        part_number: u32,
        /// Expected checksum in normalized lowercase form.
        expected_checksum: String,
        /// Actual checksum returned by the backend in normalized lowercase form.
        actual_checksum: String,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// A backend-reported ETag did not match the expected checksum.
    #[error(
        "upload part {part_number} etag mismatch: expected={expected_etag} actual={actual_etag}"
    )]
    PartEtagMismatch {
        /// One-based part number.
        part_number: u32,
        /// Expected ETag in normalized lowercase form.
        expected_etag: String,
        /// Actual ETag returned by the backend in normalized lowercase form.
        actual_etag: String,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// Completing the remote upload session failed.
    #[error("failed to complete resumable upload: {source}")]
    CompleteFailed {
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
        #[source]
        /// Source error returned by the backend.
        source: E,
    },
    /// The source stream produced no uploadable data.
    #[error("upload body produced no parts")]
    EmptyUploadBody,
    /// A required completed part was missing from the checkpoint.
    #[error("missing completed metadata for part {part_number}")]
    MissingCompletedPart {
        /// Missing one-based part number.
        part_number: u32,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
    /// The source stream requires more parts than this checkpoint format can represent.
    #[error(
        "resumable upload requires part {attempted_part_number}, which exceeds max supported part number {max_part_number}"
    )]
    TooManyUploadParts {
        /// One-based part number that would have been needed.
        attempted_part_number: u64,
        /// Maximum one-based part number supported by the checkpoint format.
        max_part_number: u32,
        /// Last known checkpoint state.
        checkpoint: ResumableUploadCheckpoint,
    },
}

impl<E> ResumableUploadError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Returns the checkpoint carried by this error, when available.
    pub fn checkpoint(&self) -> Option<&ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartNumberMismatch { checkpoint, .. }
            | Self::PartSizeMismatch { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::MissingCompletedPart { checkpoint, .. }
            | Self::TooManyUploadParts { checkpoint, .. } => Some(checkpoint),
            _ => None,
        }
    }

    /// Consumes the error and returns the checkpoint carried by it, when available.
    pub fn into_checkpoint(self) -> Option<ResumableUploadCheckpoint> {
        match self {
            Self::SourceRead { checkpoint, .. }
            | Self::PartUploadFailed { checkpoint, .. }
            | Self::PartNumberMismatch { checkpoint, .. }
            | Self::PartSizeMismatch { checkpoint, .. }
            | Self::PartChecksumMismatch { checkpoint, .. }
            | Self::PartEtagMismatch { checkpoint, .. }
            | Self::CompleteFailed { checkpoint, .. }
            | Self::MissingCompletedPart { checkpoint, .. }
            | Self::TooManyUploadParts { checkpoint, .. } => Some(checkpoint),
            _ => None,
        }
    }
}

/// Backend contract for blocking resumable uploads.
pub trait BlockingResumableUploadBackend {
    /// Backend-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Starts a new remote upload session and returns its upload id.
    fn create_upload(&self) -> Result<String, Self::Error>;

    /// Uploads one part and returns metadata for the completed part.
    ///
    /// The returned `part_number` and `size` must match the requested part.
    fn upload_part(
        &self,
        upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> Result<UploadedPart, Self::Error>;

    /// Finalizes the remote upload using the ordered completed parts.
    fn complete_upload(&self, upload_id: &str, parts: &[UploadedPart]) -> Result<(), Self::Error>;

    /// Aborts a remote upload session after a terminal error.
    fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Backend contract for async resumable uploads.
#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub trait AsyncResumableUploadBackend {
    /// Backend-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Starts a new remote upload session and returns its upload id.
    fn create_upload(&self) -> impl Future<Output = Result<String, Self::Error>> + Send;

    /// Uploads one part and returns metadata for the completed part.
    ///
    /// The returned `part_number` and `size` must match the requested part.
    fn upload_part(
        &self,
        upload_id: &str,
        part_number: u32,
        chunk: &[u8],
    ) -> impl Future<Output = Result<UploadedPart, Self::Error>> + Send;

    /// Finalizes the remote upload using the ordered completed parts.
    fn complete_upload(
        &self,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Aborts a remote upload session after a terminal error.
    fn abort_upload(
        &self,
        _upload_id: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }
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
        (Some(checkpoint_algorithm), None) => {
            return Err(ResumableUploadError::CheckpointChecksumAlgorithmMismatch {
                checkpoint_checksum_algorithm: checkpoint_algorithm.as_str(),
                options_checksum_algorithm: "none",
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

    normalize_checkpoint_part_numbers(checkpoint);

    Ok(())
}

fn normalize_checkpoint_part_numbers(checkpoint: &mut ResumableUploadCheckpoint) {
    checkpoint.completed_parts.retain(|part_number, part| {
        if *part_number == 0 {
            return false;
        }
        part.part_number = *part_number;
        true
    });
}

fn checkpoint_part_matches(
    existing: &UploadedPart,
    expected_size: usize,
    expected_checksum: Option<&str>,
    verify_remote_etag: bool,
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

    let normalized_expected = normalize_token(expected_checksum);
    if normalize_token(existing_checksum) != normalized_expected {
        return false;
    }

    !verify_remote_etag || normalize_token(&existing.etag) == normalized_expected
}

fn checkpoint_has_remaining_parts(
    checkpoint: &ResumableUploadCheckpoint,
    next_part_number: u64,
) -> Option<u32> {
    let next_part_number = u32::try_from(next_part_number).ok()?;
    checkpoint
        .completed_parts
        .range(next_part_number..)
        .next()
        .map(|(&part_number, _)| part_number)
}

fn read_chunk<R>(reader: &mut R, part_size: usize) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut buffer = vec![0_u8; part_size];
    let mut read_len = 0_usize;

    while read_len < part_size {
        let read = read_retry_interrupted(reader, &mut buffer[read_len..])?;
        if read == 0 {
            break;
        }
        read_len = read_len.saturating_add(read);
    }

    buffer.truncate(read_len);
    Ok(buffer)
}

#[cfg(feature = "_async")]
async fn read_chunk_async<R>(reader: &mut R, part_size: usize) -> io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; part_size];
    let mut read_len = 0_usize;

    while read_len < part_size {
        let read = read_async_retry_interrupted(reader, &mut buffer[read_len..]).await?;
        if read == 0 {
            break;
        }
        read_len = read_len.saturating_add(read);
    }

    buffer.truncate(read_len);
    Ok(buffer)
}

struct UploadPartPlan {
    part_number: u32,
    chunk: Vec<u8>,
    expected_checksum: Option<String>,
}

enum UploadChunkAction {
    Finish,
    Skip,
    Upload(UploadPartPlan),
}

struct UploadPartRetry<'a> {
    options: &'a ResumableUploadOptions,
    attempt: usize,
}

impl<'a> UploadPartRetry<'a> {
    const fn new(options: &'a ResumableUploadOptions) -> Self {
        Self {
            options,
            attempt: 1,
        }
    }

    fn record_failure<E>(
        &mut self,
        session: &ResumableUploadSession<'_>,
        plan: &UploadPartPlan,
        source: E,
    ) -> Result<Duration, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if self.attempt >= self.options.max_attempts {
            return Err(session.part_upload_failed(plan, self.attempt, source));
        }

        let delay = self.options.backoff_for_retry(self.attempt);
        self.attempt += 1;
        Ok(delay)
    }
}

struct ResumableUploadSession<'a> {
    options: &'a ResumableUploadOptions,
    checkpoint: ResumableUploadCheckpoint,
    resumed: bool,
    total_bytes: u64,
    part_number: u64,
}

impl<'a> ResumableUploadSession<'a> {
    fn new<E>(
        options: &'a ResumableUploadOptions,
        mut checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<Self, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        options.validate::<E>()?;
        validate_and_upgrade_checkpoint::<E>(options, &mut checkpoint)?;
        Ok(Self {
            options,
            checkpoint,
            resumed,
            total_bytes: 0,
            part_number: 1,
        })
    }

    fn upload_id(&self) -> &str {
        &self.checkpoint.upload_id
    }

    fn next_chunk<E>(
        &mut self,
        chunk: Vec<u8>,
    ) -> Result<UploadChunkAction, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if chunk.is_empty() {
            if let Some(expected_part_number) =
                checkpoint_has_remaining_parts(&self.checkpoint, self.part_number)
            {
                return Err(ResumableUploadError::SourceRead {
                    source: io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("source ended before checkpointed part {expected_part_number}"),
                    ),
                    checkpoint: self.checkpoint.clone(),
                });
            }
            return Ok(UploadChunkAction::Finish);
        }

        let part_number = self.current_part_number::<E>()?;
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        let expected_checksum = self.options.expected_checksum(&chunk);
        if let Some(existing) = self.checkpoint.completed_parts.get(&part_number)
            && checkpoint_part_matches(
                existing,
                chunk.len(),
                expected_checksum.as_deref(),
                self.options.verify_remote_etag(),
            )
        {
            self.advance_part_number();
            return Ok(UploadChunkAction::Skip);
        }

        Ok(UploadChunkAction::Upload(UploadPartPlan {
            part_number,
            chunk,
            expected_checksum,
        }))
    }

    fn accept_uploaded_part<E>(
        &mut self,
        plan: &UploadPartPlan,
        uploaded: UploadedPart,
    ) -> Result<(), ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if uploaded.part_number != plan.part_number {
            return Err(ResumableUploadError::PartNumberMismatch {
                expected_part_number: plan.part_number,
                actual_part_number: uploaded.part_number,
                checkpoint: self.checkpoint.clone(),
            });
        }
        if uploaded.size != plan.chunk.len() {
            return Err(ResumableUploadError::PartSizeMismatch {
                part_number: plan.part_number,
                expected_size: plan.chunk.len(),
                actual_size: uploaded.size,
                checkpoint: self.checkpoint.clone(),
            });
        }

        let mut uploaded = uploaded;
        self.options.validate_uploaded_part::<E>(
            &self.checkpoint,
            plan.part_number,
            &uploaded,
            plan.expected_checksum.as_deref(),
        )?;
        if uploaded.checksum.is_none() {
            uploaded.checksum = plan.expected_checksum.clone();
        }
        self.checkpoint
            .completed_parts
            .insert(plan.part_number, uploaded);
        self.advance_part_number();
        Ok(())
    }

    fn source_read_error<E>(&self, source: io::Error) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::SourceRead {
            source,
            checkpoint: self.checkpoint.clone(),
        }
    }

    fn part_upload_failed<E>(
        &self,
        plan: &UploadPartPlan,
        attempts: usize,
        source: E,
    ) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::PartUploadFailed {
            part_number: plan.part_number,
            attempts,
            checkpoint: self.checkpoint.clone(),
            source,
        }
    }

    fn complete_upload_failed<E>(&self, source: E) -> ResumableUploadError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ResumableUploadError::CompleteFailed {
            checkpoint: self.checkpoint.clone(),
            source,
        }
    }

    fn ordered_parts<E>(&self) -> Result<Vec<UploadedPart>, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let total_parts = self.total_parts();
        let mut ordered_parts = Vec::with_capacity(total_parts as usize);
        for current in 1..=total_parts {
            let Some(part) = self.checkpoint.completed_parts.get(&current) else {
                return Err(ResumableUploadError::MissingCompletedPart {
                    part_number: current,
                    checkpoint: self.checkpoint.clone(),
                });
            };
            ordered_parts.push(part.clone());
        }
        Ok(ordered_parts)
    }

    fn ordered_completed_parts<E>(&self) -> Result<Vec<UploadedPart>, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if self.total_parts() == 0 {
            return Err(ResumableUploadError::EmptyUploadBody);
        }
        self.ordered_parts()
    }

    fn total_parts(&self) -> u32 {
        self.part_number
            .saturating_sub(1)
            .min(u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER)) as u32
    }

    fn finish(self, completed_parts: Vec<UploadedPart>) -> ResumableUploadResult {
        let total_parts = self.total_parts();
        ResumableUploadResult {
            upload_id: self.checkpoint.upload_id,
            total_bytes: self.total_bytes,
            total_parts,
            resumed: self.resumed,
            completed_parts,
        }
    }

    fn current_part_number<E>(&self) -> Result<u32, ResumableUploadError<E>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        u32::try_from(self.part_number).map_err(|_| ResumableUploadError::TooManyUploadParts {
            attempted_part_number: self.part_number,
            max_part_number: MAX_RESUMABLE_UPLOAD_PART_NUMBER,
            checkpoint: self.checkpoint.clone(),
        })
    }

    fn advance_part_number(&mut self) {
        self.part_number += 1;
    }
}

/// Blocking helper that drives a multipart upload with checkpoints and retries.
pub struct BlockingResumableUploader {
    options: ResumableUploadOptions,
}

impl BlockingResumableUploader {
    /// Creates a new uploader with the provided options.
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    /// Returns the options used by this uploader.
    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }

    /// Starts a new resumable upload.
    pub fn upload<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        self.options.validate::<B::Error>()?;
        let upload_id = backend
            .create_upload()
            .map_err(|source| ResumableUploadError::CreateFailed { source })?;
        let mut checkpoint = ResumableUploadCheckpoint::new(upload_id, self.options.part_size);
        checkpoint.checksum_algorithm = self.options.part_checksum_algorithm();
        self.upload_with_checkpoint(backend, reader, checkpoint, false)
    }

    /// Resumes an upload from an existing checkpoint.
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

    fn abort_if_configured<B>(&self, backend: &B, upload_id: &str)
    where
        B: BlockingResumableUploadBackend,
    {
        if self.options.abort_on_error {
            let _ = backend.abort_upload(upload_id);
        }
    }

    fn upload_with_checkpoint<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
        R: Read,
    {
        let mut session =
            ResumableUploadSession::new::<B::Error>(&self.options, checkpoint, resumed)?;

        loop {
            let chunk = match read_chunk(reader, self.options.part_size) {
                Ok(chunk) => chunk,
                Err(source) => {
                    self.abort_if_configured(backend, session.upload_id());
                    return Err(session.source_read_error(source));
                }
            };

            let action = match session.next_chunk::<B::Error>(chunk) {
                Ok(action) => action,
                Err(error) => {
                    self.abort_if_configured(backend, session.upload_id());
                    return Err(error);
                }
            };

            match action {
                UploadChunkAction::Finish => break,
                UploadChunkAction::Skip => continue,
                UploadChunkAction::Upload(plan) => {
                    let uploaded = self.upload_part_with_retries(backend, &session, &plan)?;
                    if let Err(error) = session.accept_uploaded_part::<B::Error>(&plan, uploaded) {
                        self.abort_if_configured(backend, session.upload_id());
                        return Err(error);
                    }
                }
            }
        }

        let ordered_parts = match session.ordered_completed_parts::<B::Error>() {
            Ok(parts) => parts,
            Err(error) => {
                self.abort_if_configured(backend, session.upload_id());
                return Err(error);
            }
        };

        if let Err(source) = backend.complete_upload(session.upload_id(), &ordered_parts) {
            self.abort_if_configured(backend, session.upload_id());
            return Err(session.complete_upload_failed(source));
        }

        Ok(session.finish(ordered_parts))
    }

    fn upload_part_with_retries<B>(
        &self,
        backend: &B,
        session: &ResumableUploadSession<'_>,
        plan: &UploadPartPlan,
    ) -> Result<UploadedPart, ResumableUploadError<B::Error>>
    where
        B: BlockingResumableUploadBackend,
    {
        let mut retry = UploadPartRetry::new(&self.options);
        loop {
            match backend.upload_part(session.upload_id(), plan.part_number, &plan.chunk) {
                Ok(part) => return Ok(part),
                Err(source) => match retry.record_failure(session, plan, source) {
                    Ok(delay) => {
                        if !delay.is_zero() {
                            sleep(delay);
                        }
                    }
                    Err(error) => {
                        self.abort_if_configured(backend, session.upload_id());
                        return Err(error);
                    }
                },
            }
        }
    }
}

impl Default for BlockingResumableUploader {
    fn default() -> Self {
        Self::new(ResumableUploadOptions::default())
    }
}

#[cfg(feature = "_async")]
/// Async helper that drives a multipart upload with checkpoints and retries.
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub struct AsyncResumableUploader {
    options: ResumableUploadOptions,
}

#[cfg(feature = "_async")]
impl AsyncResumableUploader {
    /// Creates a new uploader with the provided options.
    pub fn new(options: ResumableUploadOptions) -> Self {
        Self { options }
    }

    /// Returns the options used by this uploader.
    pub fn options(&self) -> &ResumableUploadOptions {
        &self.options
    }

    /// Starts a new resumable upload.
    pub async fn upload<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.options.validate::<B::Error>()?;
        let upload_id = backend
            .create_upload()
            .await
            .map_err(|source| ResumableUploadError::CreateFailed { source })?;
        let mut checkpoint = ResumableUploadCheckpoint::new(upload_id, self.options.part_size);
        checkpoint.checksum_algorithm = self.options.part_checksum_algorithm();
        self.upload_with_checkpoint(backend, reader, checkpoint, false)
            .await
    }

    /// Resumes an upload from an existing checkpoint.
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

    async fn abort_if_configured<B>(&self, backend: &B, upload_id: &str)
    where
        B: AsyncResumableUploadBackend,
    {
        if self.options.abort_on_error {
            let _ = backend.abort_upload(upload_id).await;
        }
    }

    async fn upload_with_checkpoint<B, R>(
        &self,
        backend: &B,
        reader: &mut R,
        checkpoint: ResumableUploadCheckpoint,
        resumed: bool,
    ) -> Result<ResumableUploadResult, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut session =
            ResumableUploadSession::new::<B::Error>(&self.options, checkpoint, resumed)?;

        loop {
            let chunk = match read_chunk_async(reader, self.options.part_size).await {
                Ok(chunk) => chunk,
                Err(source) => {
                    self.abort_if_configured(backend, session.upload_id()).await;
                    return Err(session.source_read_error(source));
                }
            };

            let action = match session.next_chunk::<B::Error>(chunk) {
                Ok(action) => action,
                Err(error) => {
                    self.abort_if_configured(backend, session.upload_id()).await;
                    return Err(error);
                }
            };

            match action {
                UploadChunkAction::Finish => break,
                UploadChunkAction::Skip => continue,
                UploadChunkAction::Upload(plan) => {
                    let uploaded = self
                        .upload_part_with_retries(backend, &session, &plan)
                        .await?;
                    if let Err(error) = session.accept_uploaded_part::<B::Error>(&plan, uploaded) {
                        self.abort_if_configured(backend, session.upload_id()).await;
                        return Err(error);
                    }
                }
            }
        }

        let ordered_parts = match session.ordered_completed_parts::<B::Error>() {
            Ok(parts) => parts,
            Err(error) => {
                self.abort_if_configured(backend, session.upload_id()).await;
                return Err(error);
            }
        };

        if let Err(source) = backend
            .complete_upload(session.upload_id(), &ordered_parts)
            .await
        {
            self.abort_if_configured(backend, session.upload_id()).await;
            return Err(session.complete_upload_failed(source));
        }

        Ok(session.finish(ordered_parts))
    }

    async fn upload_part_with_retries<B>(
        &self,
        backend: &B,
        session: &ResumableUploadSession<'_>,
        plan: &UploadPartPlan,
    ) -> Result<UploadedPart, ResumableUploadError<B::Error>>
    where
        B: AsyncResumableUploadBackend,
    {
        let mut retry = UploadPartRetry::new(&self.options);
        loop {
            match backend
                .upload_part(session.upload_id(), plan.part_number, &plan.chunk)
                .await
            {
                Ok(part) => return Ok(part),
                Err(source) => match retry.record_failure(session, plan, source) {
                    Ok(delay) => {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    Err(error) => {
                        self.abort_if_configured(backend, session.upload_id()).await;
                        return Err(error);
                    }
                },
            }
        }
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
    use std::pin::Pin;
    #[cfg(feature = "_async")]
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[cfg(feature = "_async")]
    use std::task::{Context, Poll};

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
        fail_complete: AtomicBool,
        aborts: AtomicUsize,
        create_calls: AtomicUsize,
        completed: AtomicUsize,
        completed_payloads: Mutex<Vec<Vec<UploadedPart>>>,
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

        fn fail_complete(&self) {
            self.fail_complete.store(true, Ordering::SeqCst);
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
            parts: &[UploadedPart],
        ) -> Result<(), Self::Error> {
            if self.fail_complete.load(Ordering::SeqCst) {
                return Err(MockError::new("complete upload failed"));
            }
            self.completed_payloads
                .lock()
                .expect("lock completed_payloads")
                .push(parts.to_vec());
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FailingReader {
        chunk: Vec<u8>,
        served_chunk: bool,
    }

    impl FailingReader {
        fn new(chunk: &[u8]) -> Self {
            Self {
                chunk: chunk.to_vec(),
                served_chunk: false,
            }
        }
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.served_chunk {
                self.served_chunk = true;
                let len = self.chunk.len().min(buffer.len());
                buffer[..len].copy_from_slice(&self.chunk[..len]);
                return Ok(len);
            }

            Err(std::io::Error::other("source reader failed"))
        }
    }

    struct InterruptedOnceReader {
        data: Vec<u8>,
        offset: usize,
        interrupted: bool,
    }

    impl InterruptedOnceReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                offset: 0,
                interrupted: false,
            }
        }
    }

    impl Read for InterruptedOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            if self.offset >= self.data.len() {
                return Ok(0);
            }

            let read = buffer.len().min(self.data.len() - self.offset);
            buffer[..read].copy_from_slice(&self.data[self.offset..self.offset + read]);
            self.offset += read;
            Ok(read)
        }
    }

    #[cfg(feature = "_async")]
    struct AsyncInterruptedOnceReader {
        data: Vec<u8>,
        offset: usize,
        interrupted: bool,
    }

    #[cfg(feature = "_async")]
    impl AsyncInterruptedOnceReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                offset: 0,
                interrupted: false,
            }
        }
    }

    #[cfg(feature = "_async")]
    impl tokio::io::AsyncRead for AsyncInterruptedOnceReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let reader = self.get_mut();
            if !reader.interrupted {
                reader.interrupted = true;
                return Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
            }
            if reader.offset >= reader.data.len() {
                return Poll::Ready(Ok(()));
            }

            let read = buffer.remaining().min(reader.data.len() - reader.offset);
            buffer.put_slice(&reader.data[reader.offset..reader.offset + read]);
            reader.offset += read;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn read_chunk_retries_interrupted_reads() {
        let mut reader = InterruptedOnceReader::new(b"abcdef");

        let first = read_chunk(&mut reader, 4).expect("interrupted read should be retried");
        let second = read_chunk(&mut reader, 4).expect("remaining bytes should be readable");

        assert_eq!(first, b"abcd");
        assert_eq!(second, b"ef");
    }

    #[cfg(feature = "_async")]
    #[tokio::test]
    async fn read_chunk_async_retries_interrupted_reads() {
        let mut reader = AsyncInterruptedOnceReader::new(b"abcdef");

        let first = read_chunk_async(&mut reader, 4)
            .await
            .expect("interrupted read should be retried");
        let second = read_chunk_async(&mut reader, 4)
            .await
            .expect("remaining bytes should be readable");

        assert_eq!(first, b"abcd");
        assert_eq!(second, b"ef");
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
    fn upload_session_allows_maximum_part_number_as_final_chunk() {
        let options = ResumableUploadOptions::new()
            .with_part_size(1)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0);
        let checkpoint = ResumableUploadCheckpoint::new("upload-1", 1);
        let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
            .expect("session should be built");
        session.part_number = u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER);

        let plan = match session
            .next_chunk::<MockError>(b"x".to_vec())
            .expect("max part number should be accepted")
        {
            UploadChunkAction::Upload(plan) => plan,
            _ => panic!("max part number should produce an upload plan"),
        };
        assert_eq!(plan.part_number, MAX_RESUMABLE_UPLOAD_PART_NUMBER);

        session
            .accept_uploaded_part::<MockError>(
                &plan,
                UploadedPart {
                    part_number: plan.part_number,
                    etag: "etag-max".to_owned(),
                    size: 1,
                    checksum: None,
                },
            )
            .expect("max part number should be accepted as the final part");

        assert_eq!(session.total_parts(), MAX_RESUMABLE_UPLOAD_PART_NUMBER);
        assert!(matches!(
            session
                .next_chunk::<MockError>(Vec::new())
                .expect("empty chunk after max part should finish"),
            UploadChunkAction::Finish
        ));
    }

    #[test]
    fn upload_session_rejects_part_numbers_past_checkpoint_range() {
        let options = ResumableUploadOptions::new()
            .with_part_size(1)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0);
        let checkpoint = ResumableUploadCheckpoint::new("upload-1", 1);
        let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
            .expect("session should be built");
        session.part_number = u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER) + 1;

        let error = match session.next_chunk::<MockError>(b"x".to_vec()) {
            Ok(_) => panic!("part number overflow should be rejected"),
            Err(error) => error,
        };

        match error {
            ResumableUploadError::TooManyUploadParts {
                attempted_part_number,
                max_part_number,
                checkpoint,
            } => {
                assert_eq!(
                    attempted_part_number,
                    u64::from(MAX_RESUMABLE_UPLOAD_PART_NUMBER) + 1
                );
                assert_eq!(max_part_number, MAX_RESUMABLE_UPLOAD_PART_NUMBER);
                assert!(checkpoint.completed_parts.is_empty());
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn upload_session_rejects_backend_part_number_mismatch() {
        let options = ResumableUploadOptions::new()
            .with_part_size(4)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0);
        let checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
        let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
            .expect("session should be built");

        let plan = match session
            .next_chunk::<MockError>(b"abcd".to_vec())
            .expect("chunk should produce an upload plan")
        {
            UploadChunkAction::Upload(plan) => plan,
            _ => panic!("chunk should produce an upload plan"),
        };
        let error = session
            .accept_uploaded_part::<MockError>(
                &plan,
                UploadedPart {
                    part_number: 99,
                    etag: "etag-1".to_owned(),
                    size: 4,
                    checksum: None,
                },
            )
            .expect_err("backend part number mismatch should be rejected");

        match error {
            ResumableUploadError::PartNumberMismatch {
                expected_part_number,
                actual_part_number,
                checkpoint,
            } => {
                assert_eq!(expected_part_number, 1);
                assert_eq!(actual_part_number, 99);
                assert!(checkpoint.completed_parts.is_empty());
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn upload_session_rejects_backend_part_size_mismatch() {
        let options = ResumableUploadOptions::new()
            .with_part_size(4)
            .with_max_attempts(1)
            .with_jitter_ratio(0.0);
        let checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
        let mut session = ResumableUploadSession::new::<MockError>(&options, checkpoint, false)
            .expect("session should be built");

        let plan = match session
            .next_chunk::<MockError>(b"abcd".to_vec())
            .expect("chunk should produce an upload plan")
        {
            UploadChunkAction::Upload(plan) => plan,
            _ => panic!("chunk should produce an upload plan"),
        };
        let error = session
            .accept_uploaded_part::<MockError>(
                &plan,
                UploadedPart {
                    part_number: 1,
                    etag: "etag-1".to_owned(),
                    size: 3,
                    checksum: None,
                },
            )
            .expect_err("backend part size mismatch should be rejected");

        match error {
            ResumableUploadError::PartSizeMismatch {
                part_number,
                expected_size,
                actual_size,
                checkpoint,
            } => {
                assert_eq!(part_number, 1);
                assert_eq!(expected_size, 4);
                assert_eq!(actual_size, 3);
                assert!(checkpoint.completed_parts.is_empty());
            }
            other => panic!("unexpected error variant: {other}"),
        }
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
    fn blocking_resume_reuploads_checkpoint_part_when_verified_etag_mismatches() {
        let backend = BlockingMockBackend::default();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_verify_remote_etag(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
        checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
        checkpoint.completed_parts.insert(
            1,
            UploadedPart {
                part_number: 1,
                etag: "stale-etag".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let result = uploader
            .resume(&backend, &mut reader, checkpoint)
            .expect("resume should repair stale checkpoint etag");

        assert!(result.resumed);
        assert_eq!(result.total_parts, 2);
        let attempts = backend.attempts.lock().expect("lock attempts");
        assert_eq!(attempts.get(&1).copied(), Some(1));
        assert_eq!(attempts.get(&2).copied(), Some(1));
    }

    #[test]
    fn blocking_resume_normalizes_checkpoint_part_numbers_before_completion() {
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
            0,
            UploadedPart {
                part_number: 0,
                etag: "unused".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"zero")),
            },
        );
        checkpoint.completed_parts.insert(
            1,
            UploadedPart {
                part_number: 99,
                etag: "etag-1".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let result = uploader
            .resume(&backend, &mut reader, checkpoint)
            .expect("resume should normalize checkpoint part metadata");

        assert_eq!(result.total_parts, 1);
        assert_eq!(result.completed_parts[0].part_number, 1);
        assert_eq!(
            backend
                .attempts
                .lock()
                .expect("lock attempts")
                .get(&1)
                .copied(),
            None
        );

        let completed_payloads = backend
            .completed_payloads
            .lock()
            .expect("lock completed_payloads");
        assert_eq!(completed_payloads.len(), 1);
        assert_eq!(completed_payloads[0].len(), 1);
        assert_eq!(completed_payloads[0][0].part_number, 1);
    }

    #[test]
    fn blocking_resume_rejects_checkpoint_that_is_ahead_of_source() {
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
        checkpoint.completed_parts.insert(
            2,
            UploadedPart {
                part_number: 2,
                etag: "etag-2".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"efgh")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .resume(&backend, &mut reader, checkpoint)
            .expect_err("resume should reject checkpoints that run past the source");

        match error {
            ResumableUploadError::SourceRead { source, checkpoint } => {
                assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
                assert_eq!(checkpoint.completed_parts.len(), 2);
            }
            other => panic!("unexpected error variant: {other}"),
        }
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
    fn blocking_upload_rejects_invalid_options_before_create_upload() {
        let backend = BlockingMockBackend::default();
        let uploader =
            BlockingResumableUploader::new(ResumableUploadOptions::new().with_part_size(0));

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("invalid options should fail before creating an upload");

        match error {
            ResumableUploadError::InvalidOptions {
                part_size, message, ..
            } => {
                assert_eq!(part_size, 0);
                assert_eq!(message, "part_size must be greater than zero");
            }
            other => panic!("unexpected error variant: {other}"),
        }
        assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.aborts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resumable_upload_options_reject_incoherent_backoff_window() {
        let options = ResumableUploadOptions::new()
            .with_base_backoff(Duration::from_millis(80))
            .with_max_backoff(Duration::from_millis(50));

        let error = options
            .validate::<MockError>()
            .expect_err("max backoff below base backoff should be invalid");

        match error {
            ResumableUploadError::InvalidOptions {
                base_backoff_ms,
                max_backoff_ms,
                message,
                ..
            } => {
                assert_eq!(base_backoff_ms, 80);
                assert_eq!(max_backoff_ms, 50);
                assert_eq!(
                    message,
                    "max_backoff must be greater than or equal to base_backoff"
                );
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn blocking_abort_on_error_aborts_after_source_read_failure() {
        let backend = BlockingMockBackend::default();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_abort_on_error(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut reader = FailingReader::new(b"abcd");
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("upload should fail when the source reader errors");

        match error {
            ResumableUploadError::SourceRead { checkpoint, .. } => {
                assert_eq!(checkpoint.completed_parts.len(), 1);
            }
            other => panic!("unexpected error variant: {other}"),
        }

        assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn blocking_abort_on_error_aborts_after_complete_failure() {
        let backend = BlockingMockBackend::default();
        backend.fail_complete();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_abort_on_error(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("upload should fail when completion fails");

        match error {
            ResumableUploadError::CompleteFailed { checkpoint, .. } => {
                assert_eq!(checkpoint.completed_parts.len(), 1);
            }
            other => panic!("unexpected error variant: {other}"),
        }

        assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn blocking_abort_on_error_aborts_empty_upload_body() {
        let backend = BlockingMockBackend::default();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_abort_on_error(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        let error = uploader
            .upload(&backend, &mut reader)
            .expect_err("empty uploads should fail");

        match error {
            ResumableUploadError::EmptyUploadBody => {}
            other => panic!("unexpected error variant: {other}"),
        }

        assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
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
    fn blocking_checkpoint_checksum_algorithm_downgrade_is_rejected() {
        let backend = BlockingMockBackend::default();
        let uploader = BlockingResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-1", 4);
        checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .resume(&backend, &mut reader, checkpoint)
            .expect_err("resume should reject checksum algorithm downgrade");

        match error {
            ResumableUploadError::CheckpointChecksumAlgorithmMismatch {
                checkpoint_checksum_algorithm,
                options_checksum_algorithm,
            } => {
                assert_eq!(checkpoint_checksum_algorithm, "md5");
                assert_eq!(options_checksum_algorithm, "none");
            }
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

    #[test]
    fn resumable_upload_jittered_backoff_never_exceeds_max_backoff() {
        let options = ResumableUploadOptions::new()
            .with_base_backoff(Duration::from_millis(50))
            .with_max_backoff(Duration::from_millis(80))
            .with_jitter_ratio(1.0);

        for _ in 0..256 {
            let backoff = options.backoff_for_retry(4);
            assert!(backoff <= Duration::from_millis(80));
        }
    }

    #[test]
    fn resumable_upload_options_reject_nan_jitter_ratio() {
        let options = ResumableUploadOptions::new()
            .with_base_backoff(Duration::from_millis(50))
            .with_max_backoff(Duration::from_millis(80))
            .with_jitter_ratio(f64::NAN);

        let error = options
            .validate::<MockError>()
            .expect_err("nan jitter ratio should be invalid");

        match error {
            ResumableUploadError::InvalidOptions {
                jitter_ratio,
                message,
                ..
            } => {
                assert!(jitter_ratio.is_nan());
                assert_eq!(
                    message,
                    "jitter_ratio must be finite and between 0.0 and 1.0"
                );
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn resumable_upload_options_reject_etag_verification_without_checksum() {
        let options = ResumableUploadOptions::new().with_verify_remote_etag(true);

        let error = options
            .validate::<MockError>()
            .expect_err("etag verification without checksums should be invalid");

        match error {
            ResumableUploadError::InvalidOptions { message, .. } => {
                assert_eq!(
                    message,
                    "verify_remote_etag requires part_checksum_algorithm"
                );
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
        fail_complete: Arc<AtomicBool>,
        aborts: Arc<AtomicUsize>,
        create_calls: Arc<AtomicUsize>,
        completed: Arc<AtomicUsize>,
        completed_payloads: Arc<Mutex<Vec<Vec<UploadedPart>>>>,
    }

    #[cfg(feature = "_async")]
    impl AsyncMockBackend {
        fn fail_once_for_part(&self, part_number: u32) {
            let mut fail_once = self.fail_once_parts.lock().expect("lock fail_once_parts");
            fail_once.insert(part_number);
        }

        fn fail_complete(&self) {
            self.fail_complete.store(true, Ordering::SeqCst);
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
            parts: &[UploadedPart],
        ) -> Result<(), Self::Error> {
            if self.fail_complete.load(Ordering::SeqCst) {
                return Err(MockError::new("complete upload failed"));
            }
            self.completed_payloads
                .lock()
                .expect("lock completed_payloads")
                .push(parts.to_vec());
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn abort_upload(&self, _upload_id: &str) -> Result<(), Self::Error> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
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

    #[cfg(feature = "_async")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_upload_rejects_invalid_options_before_create_upload() {
        let backend = AsyncMockBackend::default();
        let uploader =
            AsyncResumableUploader::new(ResumableUploadOptions::new().with_max_attempts(0));

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .await
            .expect_err("invalid options should fail before creating an upload");

        match error {
            ResumableUploadError::InvalidOptions {
                max_attempts,
                message,
                ..
            } => {
                assert_eq!(max_attempts, 0);
                assert_eq!(message, "max_attempts must be greater than zero");
            }
            other => panic!("unexpected error variant: {other}"),
        }
        assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.aborts.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "_async")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_resume_reuploads_checkpoint_part_when_verified_etag_mismatches() {
        let backend = AsyncMockBackend::default();
        let uploader = AsyncResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_verify_remote_etag(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-async-1", 4);
        checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
        checkpoint.completed_parts.insert(
            1,
            UploadedPart {
                part_number: 1,
                etag: "stale-etag".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let result = uploader
            .resume(&backend, &mut reader, checkpoint)
            .await
            .expect("resume should repair stale checkpoint etag");

        assert!(result.resumed);
        assert_eq!(result.total_parts, 2);
        let attempts = backend.attempts.lock().expect("lock attempts");
        assert_eq!(attempts.get(&1).copied(), Some(1));
        assert_eq!(attempts.get(&2).copied(), Some(1));
    }

    #[cfg(feature = "_async")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_resume_normalizes_checkpoint_part_numbers_before_completion() {
        let backend = AsyncMockBackend::default();
        let uploader = AsyncResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-async-1", 4);
        checkpoint.checksum_algorithm = Some(PartChecksumAlgorithm::Md5);
        checkpoint.completed_parts.insert(
            0,
            UploadedPart {
                part_number: 0,
                etag: "unused".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"zero")),
            },
        );
        checkpoint.completed_parts.insert(
            1,
            UploadedPart {
                part_number: 99,
                etag: "etag-1".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"abcd")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let result = uploader
            .resume(&backend, &mut reader, checkpoint)
            .await
            .expect("resume should normalize checkpoint part metadata");

        assert_eq!(result.total_parts, 1);
        assert_eq!(result.completed_parts[0].part_number, 1);
        assert_eq!(
            backend
                .attempts
                .lock()
                .expect("lock attempts")
                .get(&1)
                .copied(),
            None
        );

        let completed_payloads = backend
            .completed_payloads
            .lock()
            .expect("lock completed_payloads");
        assert_eq!(completed_payloads.len(), 1);
        assert_eq!(completed_payloads[0].len(), 1);
        assert_eq!(completed_payloads[0][0].part_number, 1);
    }

    #[cfg(feature = "_async")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_resume_rejects_checkpoint_that_is_ahead_of_source() {
        let backend = AsyncMockBackend::default();
        let uploader = AsyncResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_part_checksum_algorithm(PartChecksumAlgorithm::Md5)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut checkpoint = ResumableUploadCheckpoint::new("upload-async-1", 4);
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
        checkpoint.completed_parts.insert(
            2,
            UploadedPart {
                part_number: 2,
                etag: "etag-2".to_owned(),
                size: 4,
                checksum: Some(PartChecksumAlgorithm::Md5.compute_hex(b"efgh")),
            },
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .resume(&backend, &mut reader, checkpoint)
            .await
            .expect_err("resume should reject checkpoints that run past the source");

        match error {
            ResumableUploadError::SourceRead { source, checkpoint } => {
                assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
                assert_eq!(checkpoint.completed_parts.len(), 2);
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[cfg(feature = "_async")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_abort_on_error_aborts_after_complete_failure() {
        let backend = AsyncMockBackend::default();
        backend.fail_complete();
        let uploader = AsyncResumableUploader::new(
            ResumableUploadOptions::new()
                .with_part_size(4)
                .with_abort_on_error(true)
                .with_max_attempts(1)
                .with_jitter_ratio(0.0),
        );

        let mut reader = std::io::Cursor::new(b"abcd".to_vec());
        let error = uploader
            .upload(&backend, &mut reader)
            .await
            .expect_err("upload should fail when completion fails");

        match error {
            ResumableUploadError::CompleteFailed { checkpoint, .. } => {
                assert_eq!(checkpoint.completed_parts.len(), 1);
            }
            other => panic!("unexpected error variant: {other}"),
        }

        assert_eq!(backend.aborts.load(Ordering::SeqCst), 1);
    }
}
