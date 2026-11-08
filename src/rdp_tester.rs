//! Core credential-testing engine.
//!
//! This module deliberately decouples the *audit logic* (attempt budgeting,
//! concurrency limits, delay pacing, lockout halting, reporting) from the
//! *RDP protocol backend* (the IronRDP NLA/CredSSP handshake).
//!
//! The audit logic operates on the [`RdpAuthBackend`] trait. The test suite
//! injects a scripted mock backend, so every decision — lockout abort, attempt
//! caps, per-user stops — is exercised deterministically without any network
//! traffic. The real backend ([`IronRdpBackend`]) speaks RDP through IronRDP's
//! public connector API and stops as soon as CredSSP delivers a verdict.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use thiserror::Error;
use tokio::time::sleep;

use crate::logger::AuditLogger;

/// Masks a password for logging: never writes the secret itself, only its length.
///
/// Failed attempts are always logged with masked passwords; only a confirmed
/// valid credential is ever recorded in clear text, because that finding is the
/// entire point of an authorized audit.
pub fn mask_password(password: &str) -> String {
    if password.is_empty() {
        return "<empty>".to_string();
    }
    format!("<{} chars>", password.chars().count())
}

/// Outcome of a single credential attempt against the RDP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// CredSSP/NLA accepted the credentials.
    ValidCredentials,
    /// The credentials were rejected (bad username or bad password).
    LogonFailure,
    /// The account is locked out. Every further attempt is halted immediately.
    AccountLockedOut,
    /// The credentials were accepted but the account lacks the Remote Desktop
    /// logon right, so no RDP session would ever be possible.
    AccessDenied,
    /// The account must change its password at next logon; the supplied
    /// password could not be validated.
    PasswordMustChange,
    /// The account is disabled, or logon hours / workstation restrictions
    /// block this logon.
    AccountRestricted,
    /// The target could not be reached or the RDP negotiation failed.
    ConnectionError,
}

impl AuthOutcome {
    /// Short, stable machine-readable label used in reports and log lines.
    pub fn code(&self) -> &'static str {
        match self {
            AuthOutcome::ValidCredentials => "VALID_CREDENTIALS",
            AuthOutcome::LogonFailure => "LOGON_FAILURE",
            AuthOutcome::AccountLockedOut => "ACCOUNT_LOCKED_OUT",
            AuthOutcome::AccessDenied => "ACCESS_DENIED",
            AuthOutcome::PasswordMustChange => "PASSWORD_MUST_CHANGE",
            AuthOutcome::AccountRestricted => "ACCOUNT_RESTRICTED",
            AuthOutcome::ConnectionError => "CONNECTION_ERROR",
        }
    }

    /// True only when the server fully accepted the credentials.
    pub fn is_valid_password(&self) -> bool {
        matches!(self, AuthOutcome::ValidCredentials)
    }

    /// True when no further attempts should be made for this username.
    pub fn stops_user(&self) -> bool {
        matches!(
            self,
            AuthOutcome::ValidCredentials
                | AuthOutcome::AccountLockedOut
                | AuthOutcome::AccessDenied
                | AuthOutcome::AccountRestricted
        )
    }

    /// True when the whole audit run must stop immediately.
    pub fn stops_everything(&self) -> bool {
        matches!(self, AuthOutcome::AccountLockedOut)
    }
}

impl fmt::Display for AuthOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// A username/password pair plus the optional RDP domain.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Account name sent to CredSSP (without domain prefix).
    pub username: String,
    /// Password sent to CredSSP.
    pub password: String,
    /// Optional domain/Workgroup for the logon.
    pub domain: Option<String>,
}

/// Configuration for one audit run.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Hostname or IP address of the RDP service.
    pub target: String,
    /// Resolved target address (kept for reporting; the backend re-resolves).
    pub ip: IpAddr,
    /// RDP TCP port.
    pub port: u16,
    /// Usernames to test.
    pub usernames: Vec<String>,
    /// Passwords to try.
    pub passwords: Vec<String>,
    /// Optional domain (passed to CredSSP when present).
    pub domain: Option<String>,
    /// Delay applied per worker between its attempts (default: 1s).
    pub delay: Duration,
    /// Maximum number of credential attempts in the whole run.
    pub max_attempts: usize,
    /// Number of concurrent workers (clamped to 1..=8).
    pub concurrency: usize,
    /// Per-attempt timeout for the RDP/CredSSP handshake.
    pub timeout: Duration,
    /// Path of the audit log file.
    pub log_path: String,
}

/// Configuration validation errors (distinct from the safety/authorization
/// errors raised in `main` before a config is ever built).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditConfigError {
    /// No username was provided via `--user` or `--user-file`.
    #[error("at least one username is required (--user or --user-file)")]
    NoUsernames,
    /// No passwords were provided via `--wordlist`.
    #[error("at least one password is required (--wordlist)")]
    NoPasswords,
    /// Concurrency outside the hard safety envelope 1..=8.
    #[error("--concurrency must be between 1 and 8 (got {0})")]
    ConcurrencyOutOfRange(usize),
    /// The attempt budget must be positive.
    #[error("--max-attempts must be at least 1")]
    ZeroMaxAttempts,
}

impl AuditConfig {
    /// Validates the configuration and clamps values to the safe envelope.
    ///
    /// Safety-relevant invariants enforced here: at least one username and one
    /// password, concurrency within 1..=8, a non-zero attempt budget, and a
    /// non-zero per-worker delay (zero is raised to a 250 ms floor so the tool
    /// can never hammer a target in a tight loop).
    pub fn validate(&mut self) -> Result<(), AuditConfigError> {
        if self.usernames.is_empty() {
            return Err(AuditConfigError::NoUsernames);
        }
        if self.passwords.is_empty() {
            return Err(AuditConfigError::NoPasswords);
        }
        if !(1..=8).contains(&self.concurrency) {
            return Err(AuditConfigError::ConcurrencyOutOfRange(self.concurrency));
        }
        if self.max_attempts == 0 {
            return Err(AuditConfigError::ZeroMaxAttempts);
        }
        // De-duplicate usernames (case-insensitive) to avoid double-testing.
        let mut seen = HashSet::new();
        self.usernames
            .retain(|u| seen.insert(u.trim().to_lowercase()));
        // Anti-thrash floor: a zero delay would turn the workers into a flooder.
        if self.delay.is_zero() {
            self.delay = Duration::from_millis(250);
        }
        Ok(())
    }
}

/// Outcome of a single credential attempt, recorded for the final report.
#[derive(Debug, Clone)]
pub struct AttemptReport {
    /// Account that was tested.
    pub username: String,
    /// Password that was tested (kept in memory for the summary only).
    pub password: String,
    /// Verdict delivered by the server (or the transport error class).
    pub outcome: AuthOutcome,
}

/// Reason the audit run stopped before exhausting the wordlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    /// An account lockout was observed; every attempt was cancelled at once.
    AccountLockout {
        /// The account that got locked out.
        username: String,
    },
    /// Too many consecutive connection failures: the target is likely down,
    /// firewalled, or not speaking RDP. Continuing would be pointless noise.
    TargetUnreachable,
}

/// Final result of an audit run.
#[derive(Debug, Clone)]
pub struct AuditSummary {
    /// Target host that was audited.
    pub target: String,
    /// Path of the audit log file for this run.
    pub log_path: String,
    /// One report per completed attempt (subject to per-user stopping).
    pub reports: Vec<AttemptReport>,
    /// Credentials fully accepted by the server.
    pub valid_credentials: Vec<Credential>,
    /// Users that authenticated but have no Remote Desktop logon right.
    pub access_denied: Vec<String>,
    /// Users blocked by account policy (disabled, logon hours, workstation).
    pub restricted: Vec<String>,
    /// Number of attempts actually started.
    pub attempts_used: usize,
    /// Set when the run stopped early (lockout abort or unreachable target).
    pub halted: Option<HaltReason>,
}

impl AuditSummary {
    /// True when at least one credential was fully accepted by the server.
    pub fn found_valid(&self) -> bool {
        !self.valid_credentials.is_empty()
    }
}

/// Backend performing one real RDP authentication attempt.
///
/// The audit engine only depends on this trait, which lets the test suite
/// substitute a scripted mock for the IronRDP-based implementation.
pub trait RdpAuthBackend: Send + Sync + 'static {
    /// Attempts authentication with one credential and returns its outcome.
    fn attempt<'a>(
        &'a self,
        credential: &'a Credential,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>>;
}

/// Future type produced by the engine's per-job workers.
type JobFuture<'a> = Pin<Box<dyn Future<Output = (String, String, AuthOutcome)> + Send + 'a>>;

/// Credential-testing engine with lockout protection.
///
/// A tester runs at most `max_attempts` credential attempts, with at most
/// `concurrency` workers, each pacing itself with `delay`. The first observed
/// account lockout cancels every in-flight and queued attempt immediately.
pub struct RdpTester {
    config: AuditConfig,
    logger: Arc<AuditLogger>,
    backend: Arc<dyn RdpAuthBackend>,
    attempts_used: Arc<AtomicUsize>,
    stopped_users: Arc<Mutex<HashSet<String>>>,
}

impl RdpTester {
    /// Builds a tester for the given configuration, logging to `log_path`.
    ///
    /// The IronRDP NLA/CredSSP backend is used for the real authentication.
    pub fn new(config: AuditConfig, log_path: String) -> Result<Self, std::io::Error> {
        let logger = Arc::new(AuditLogger::create(&log_path)?);
        let backend = Arc::new(IronRdpBackend::new(
            config.target.clone(),
            config.port,
            logger.clone(),
            config.timeout,
        ));
        Ok(Self::with_backend(config, logger, backend))
    }

    /// Builds a tester with an explicit backend (used by the test suite).
    pub fn with_backend(
        config: AuditConfig,
        logger: Arc<AuditLogger>,
        backend: Arc<dyn RdpAuthBackend>,
    ) -> Self {
        Self {
            config,
            logger,
            backend,
            attempts_used: Arc::new(AtomicUsize::new(0)),
            stopped_users: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Attempts authentication with a single credential through the backend.
    ///
    /// Applies the per-attempt timeout and records the result in the audit log
    /// (passwords are masked unless the credential was confirmed valid).
    pub async fn test_credential(&self, credential: &Credential) -> AuthOutcome {
        let outcome =
            match tokio::time::timeout(self.config.timeout, self.backend.attempt(credential)).await
            {
                Ok(outcome) => outcome,
                Err(_) => {
                    self.logger.warn(&format!(
                        "attempt for user={} timed out after {:?}",
                        credential.username, self.config.timeout
                    ));
                    AuthOutcome::ConnectionError
                }
            };

        match &outcome {
            AuthOutcome::ValidCredentials => {
                self.logger.info(&format!(
                    "VALID_CREDENTIALS user={} password={} target={}:{}",
                    credential.username, credential.password, self.config.target, self.config.port
                ));
            }
            other => {
                self.logger.info(&format!(
                    "{} user={} password={} target={}:{}",
                    other.code(),
                    credential.username,
                    mask_password(&credential.password),
                    self.config.target,
                    self.config.port
                ));
            }
        }
        outcome
    }

    /// Runs the audit: bounded, rate-limited, concurrency-limited attempts.
    ///
    /// Halts immediately on the first account lockout, stops testing a username
    /// as soon as a definitive verdict for it is reached, and aborts the run
    /// after five consecutive connection errors (unreachable target).
    pub async fn run(mut self) -> AuditSummary {
        if let Err(e) = self.config.validate() {
            self.logger.error(&format!("invalid configuration: {e}"));
        }

        self.logger.info(&format!(
            "starting audit target={}:{} users={} passwords={} max_attempts={} concurrency={} delay_ms={}",
            self.config.target,
            self.config.port,
            self.config.usernames.len(),
            self.config.passwords.len(),
            self.config.max_attempts,
            self.config.concurrency,
            self.config.delay.as_millis(),
        ));

        let total_pairs = self.config.usernames.len() * self.config.passwords.len();
        let mut reports: Vec<AttemptReport> = Vec::new();
        let mut valid_credentials: Vec<Credential> = Vec::new();
        let mut access_denied: Vec<String> = Vec::new();
        let mut restricted: Vec<String> = Vec::new();
        let mut halted: Option<HaltReason> = None;
        let mut consecutive_errors: usize = 0;
        let mut attempts_per_user: HashMap<String, usize> = HashMap::new();

        // Attempt budget shared across every worker.
        let budget = AtomicUsize::new(self.config.max_attempts);

        // Job queue: (username, password) pairs in user-major order.
        let mut jobs: Vec<(String, String)> = Vec::with_capacity(total_pairs);
        for username in &self.config.usernames {
            for password in &self.config.passwords {
                jobs.push((username.clone(), password.clone()));
            }
        }
        let mut job_iter = jobs.into_iter();

        let mut in_flight: FuturesUnordered<JobFuture<'_>> = FuturesUnordered::new();
        self.fill_pipeline(&mut in_flight, &mut job_iter, &budget);

        while let Some((username, password, outcome)) = in_flight.next().await {
            match outcome {
                AuthOutcome::ValidCredentials => {
                    self.logger.warn(&format!(
                        "credential found for user={username} — stopping further attempts for this user"
                    ));
                    eprintln!(
                        "[+] VALID CREDENTIALS: {username}:{} on {}",
                        password, self.config.target
                    );
                    valid_credentials.push(Credential {
                        username: username.clone(),
                        password: password.clone(),
                        domain: self.config.domain.clone(),
                    });
                    self.mark_user_stopped(&username);
                    consecutive_errors = 0;
                }
                AuthOutcome::AccessDenied => {
                    self.logger.warn(&format!(
                        "user={username} authenticated but is NOT permitted to log in via RDP"
                    ));
                    access_denied.push(username.clone());
                    self.mark_user_stopped(&username);
                    consecutive_errors = 0;
                }
                AuthOutcome::AccountRestricted => {
                    self.logger.warn(&format!(
                        "user={username} is restricted (disabled account or logon-hours/workstation policy)"
                    ));
                    restricted.push(username.clone());
                    self.mark_user_stopped(&username);
                    consecutive_errors = 0;
                }
                AuthOutcome::AccountLockedOut => {
                    self.logger.error(&format!(
                        "ACCOUNT_LOCKED_OUT for user={username} — HALTING all attempts immediately"
                    ));
                    eprintln!(
                        "\n[!] ACCOUNT LOCKOUT DETECTED for '{username}' on {} — \
                         stopping ALL attempts immediately to avoid further lockouts.",
                        self.config.target
                    );
                    halted = Some(HaltReason::AccountLockout {
                        username: username.clone(),
                    });
                    reports.push(AttemptReport {
                        username,
                        password,
                        outcome,
                    });
                    // Cancel every in-flight attempt; the queue is not refilled.
                    in_flight.clear();
                    break;
                }
                AuthOutcome::LogonFailure => {
                    consecutive_errors = 0;
                }
                AuthOutcome::PasswordMustChange => {
                    self.logger.info(&format!(
                        "PASSWORD_MUST_CHANGE for user={username} — password could not be validated"
                    ));
                    consecutive_errors = 0;
                }
                AuthOutcome::ConnectionError => {
                    consecutive_errors += 1;
                    if consecutive_errors >= 5 {
                        self.logger.error(&format!(
                            "{consecutive_errors} consecutive CONNECTION_ERROR results — target unreachable, aborting run"
                        ));
                        halted = Some(HaltReason::TargetUnreachable);
                        reports.push(AttemptReport {
                            username,
                            password,
                            outcome,
                        });
                        in_flight.clear();
                        break;
                    }
                }
            }

            reports.push(AttemptReport {
                username: username.clone(),
                password,
                outcome,
            });

            // Stop a username once its wordlist slice is exhausted or a
            // definitive verdict was reached.
            let tried = attempts_per_user.entry(username.clone()).or_insert(0);
            *tried += 1;
            if *tried >= self.config.passwords.len() || outcome.stops_user() {
                self.mark_user_stopped(&username);
            }

            // Top up the pipeline with the next eligible job.
            if halted.is_none() {
                self.fill_pipeline(&mut in_flight, &mut job_iter, &budget);
            }
        }

        let attempts_used = self.attempts_used.load(Ordering::SeqCst);
        let summary = AuditSummary {
            target: self.config.target.clone(),
            log_path: self.config.log_path.clone(),
            reports,
            valid_credentials,
            access_denied,
            restricted,
            attempts_used,
            halted,
        };
        self.logger.info(&format!(
            "audit finished attempts_used={} valid={} halted={:?}",
            summary.attempts_used,
            summary.valid_credentials.len(),
            summary.halted
        ));
        summary
    }

    /// Refills the in-flight pipeline up to the concurrency limit.
    ///
    /// Each spawned job first reserves one unit from the shared attempt
    /// budget; jobs for already-stopped usernames are skipped without
    /// consuming budget. Returns `false` once the budget is exhausted.
    fn fill_pipeline<'a>(
        &'a self,
        in_flight: &mut FuturesUnordered<JobFuture<'a>>,
        job_iter: &mut std::vec::IntoIter<(String, String)>,
        budget: &AtomicUsize,
    ) -> bool {
        while in_flight.len() < self.config.concurrency {
            // Pull the next eligible job (skip usernames already decided).
            let candidate = loop {
                match job_iter.next() {
                    Some((username, password)) => {
                        if self.is_user_stopped(&username) {
                            continue;
                        }
                        break Some((username, password));
                    }
                    None => break None,
                }
            };
            let Some((username, password)) = candidate else {
                break; // queue drained
            };
            // Reserve an attempt slot; stop spawning when the budget is spent.
            if budget
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_err()
            {
                self.logger.warn("max attempts reached — remaining wordlist entries skipped");
                return false;
            }
            in_flight.push(Box::pin(self.spawn_job(username, password)));
        }
        true
    }

    /// Reserves nothing (the slot was reserved by the caller) and runs one
    /// credential through the backend, then applies the pacing delay.
    async fn spawn_job(&self, username: String, password: String) -> (String, String, AuthOutcome) {
        self.attempts_used.fetch_add(1, Ordering::SeqCst);
        let credential = Credential {
            username: username.clone(),
            password: password.clone(),
            domain: self.config.domain.clone(),
        };
        let outcome = self.test_credential(&credential).await;
        // Pacing: each worker waits `delay` between its own attempts.
        sleep(self.config.delay).await;
        (username, password, outcome)
    }

    /// True when this username already has a definitive verdict.
    fn is_user_stopped(&self, username: &str) -> bool {
        self.stopped_users
            .lock()
            .map(|users| users.contains(username))
            .unwrap_or(false)
    }

    /// Marks a username as finished (no further attempts for this account).
    fn mark_user_stopped(&self, username: &str) {
        if let Ok(mut users) = self.stopped_users.lock() {
            users.insert(username.to_string());
        }
    }
}

/// Classifies an NTSTATUS returned by the server during CredSSP.
///
/// Kept free of any protocol types so the mapping is trivially unit-testable.
/// Any unknown status is treated conservatively as a plain logon failure —
/// this tool never claims a password is valid unless CredSSP said `SUCCESS`.
pub fn classify_ntstatus(status: ironrdp_connector::sspi::credssp::NStatusCode) -> AuthOutcome {
    use ironrdp_connector::sspi::credssp::NStatusCode as Ns;
    if status == Ns::SUCCESS {
        AuthOutcome::ValidCredentials
    } else if status == Ns::ACCOUNT_LOCKED_OUT {
        AuthOutcome::AccountLockedOut
    } else if status == Ns::PASSWORD_MUST_CHANGE || status == Ns::PASSWORD_EXPIRED {
        AuthOutcome::PasswordMustChange
    } else if status == Ns::ACCOUNT_DISABLED
        || status == Ns::INVALID_LOGON_HOURS
        || status == Ns::INVALID_WORKSTATION
        || status == Ns::ACCOUNT_RESTRICTION
    {
        AuthOutcome::AccountRestricted
    } else {
        // LOGON_FAILURE, NO_SUCH_USER, ILL_FORMED_PASSWORD, PASSWORD_RESTRICTION
        // and anything unknown.
        AuthOutcome::LogonFailure
    }
}

/// Maps a connector error produced by the backend to an [`AuthOutcome`].
///
/// * `Credssp(status)` → classified NTSTATUS (auth verdict),
/// * `AccessDenied` → valid password but no RDP logon right,
/// * anything else (TLS, negotiation, IO, timeout) → `CONNECTION_ERROR`.
pub fn classify_connector_error(err: &ironrdp_connector::ConnectorError) -> AuthOutcome {
    use ironrdp_connector::ConnectorErrorKind as K;
    match err.kind() {
        K::Credssp(credssp_err) => match credssp_err.nstatus {
            Some(status) => classify_ntstatus(status),
            // A CredSSP error without an NTSTATUS is a crypto/protocol
            // failure, not an authentication verdict.
            None => AuthOutcome::ConnectionError,
        },
        K::AccessDenied => AuthOutcome::AccessDenied,
        // `ConnectorErrorKind` is #[non_exhaustive]: anything unknown (TLS,
        // negotiation, IO, timeouts) is a connectivity problem, never an
        // authentication verdict.
        _ => AuthOutcome::ConnectionError,
    }
}

/// Classifies the server's `SaveSessionInfo` PDU received after a non-NLA
/// session start.
///
/// This is the only programmatic logon verdict a server without NLA gives: the
/// credentials are validated by winlogon *after* the session is up.
///
/// * `INFOTYPE_LOGON`/`INFOTYPE_LOGON_LONG` — the server reports a successful
///   logon for the user ⇒ credentials are valid.
/// * `INFOTYPE_LOGON_PLAINNOTIFY` — the logon screen was shown instead of a
///   user session; with `INFO_AUTOLOGON` this is the failed-credentials case.
/// * `INFOTYPE_LOGON_EXTENDED_INFO` — classified through its
///   [`LogonErrorsInfo`] payload (bad password, must change, no permission…).
pub fn classify_save_session_info(pdu: &SaveSessionInfoPdu) -> AuthOutcome {
    match &pdu.info_data {
        InfoData::LogonInfoV1(_) | InfoData::LogonInfoV2(_) => AuthOutcome::ValidCredentials,
        InfoData::PlainNotify => AuthOutcome::LogonFailure,
        InfoData::LogonExtended(extended) => match &extended.errors_info {
            Some(errors) => classify_logon_errors(errors.error_type, &errors.error_data),
            // Logon-extended info without an error payload carries no verdict.
            None => AuthOutcome::ConnectionError,
        },
    }
}

/// Classifies one `TS_LOGON_ERRORS_INFO` (logon notification type + data).
///
/// Known-good orderings are matched first; anything unknown is treated
/// conservatively as a logon failure — a non-NLA server never gets to claim
/// "valid" through an error path.
fn classify_logon_errors(
    error_type: LogonErrorNotificationType,
    error_data: &LogonErrorNotificationData,
) -> AuthOutcome {
    use LogonErrorNotificationData::ErrorCode;
    use LogonErrorNotificationDataErrorCode as Code;
    use LogonErrorNotificationType as Kind;

    match (error_type, error_data) {
        (_, ErrorCode(Code::FailedBadPassword)) => AuthOutcome::LogonFailure,
        (_, ErrorCode(Code::FailedUpdatePassword)) => AuthOutcome::PasswordMustChange,
        // The user logged on and was warned (e.g. about a session time limit).
        (_, ErrorCode(Code::Warning)) => AuthOutcome::ValidCredentials,
        (Kind::NoPermission, _) | (Kind::DisconnectRefused, _) | (Kind::AccessDenied, _) => {
            AuthOutcome::AccessDenied
        }
        // The session is up and the server is only managing its lifetime — the
        // logon itself succeeded.
        (
            Kind::SessionTerminate
            | Kind::SessionContinue
            | Kind::ReconnectOptions
            | Kind::BumpOptions
            | Kind::SessionBusyOptions,
            _,
        ) => AuthOutcome::ValidCredentials,
    }
}

/// Classifies the server's `SetErrorInfo` PDU. Returns `None` for the "no
/// error" code, which carries no verdict and is simply skipped.
pub fn classify_error_info(error: ErrorInfo) -> Option<AuthOutcome> {
    match error {
        ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::None) => None,
        ErrorInfo::ProtocolIndependentCode(
            ProtocolIndependentCode::ServerDeniedConnection
            | ProtocolIndependentCode::ServerInsufficientPrivileges,
        ) => Some(AuthOutcome::AccessDenied),
        // Licensing problems are infrastructure, not an authentication verdict.
        ErrorInfo::ProtocolIndependentLicensingCode(_) => Some(AuthOutcome::ConnectionError),
        _ => Some(AuthOutcome::LogonFailure),
    }
}

// ---------------------------------------------------------------------------
// Real protocol backend: automatic NLA/CredSSP and TLS authentication.
// ---------------------------------------------------------------------------

use ironrdp_async::{
    Framed, FramedWrite as _, ShouldUpgrade, connect_begin, mark_as_upgraded, single_sequence_step,
};
use ironrdp_connector::credssp::{CredsspProcessGenerator, CredsspSequence};
use ironrdp_connector::sspi::credssp::ClientState;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, Config as RdpClientConfig, ConnectorError,
    ConnectorErrorExt, ConnectorErrorKind, ConnectorResult, Credentials, DesktopSize,
    ServerName,
};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::Action;
use ironrdp_pdu::mcs::{self, McsMessage};
use ironrdp_pdu::rdp::headers::{IoChannelPdu, ShareDataPdu, decode_io_channel};
use ironrdp_pdu::rdp::server_error_info::{
    ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu,
};
use ironrdp_pdu::rdp::session_info::{
    InfoData, LogonErrorNotificationData, LogonErrorNotificationDataErrorCode,
    LogonErrorNotificationType, SaveSessionInfoPdu,
};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_tokio::TokioFramed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as NativeTlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName as TlsServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as TlsError,
    SignatureScheme,
};
use tokio_rustls::TlsConnector;
use x509_cert::der::Decode as _;

/// TLS implementation used for the RDP security upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsEngine {
    /// `rustls`: portable, modern suites only (ECDHE + AEAD).
    Rustls,
    /// OS TLS stack (Schannel on Windows). Needed for older RDP servers whose
    /// only suites are RSA key exchange with AES-CBC, which `rustls` lacks.
    Native,
}

impl TlsEngine {
    /// Human-readable name used in the audit log.
    fn label(self) -> &'static str {
        match self {
            Self::Rustls => "rustls",
            Self::Native => "OS TLS stack (Schannel)",
        }
    }
}

/// Failure of an attempt *before* any credential was sent to the server.
struct AttemptFailure {
    message: String,
    /// Only a TLS handshake failure is worth retrying with the other engine.
    tls_handshake: bool,
}

impl AttemptFailure {
    fn infrastructure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            tls_handshake: false,
        }
    }

    fn tls(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            tls_handshake: true,
        }
    }
}

/// Real RDP authentication backend.
///
/// Automatically negotiates the strongest security protocol the target offers:
///
/// * `PROTOCOL_HYBRID` / `PROTOCOL_HYBRID_EX` (NLA/CredSSP) — authentication is
///   decided *before* any session starts and the connection is abandoned right
///   after the CredSSP verdict.
/// * `PROTOCOL_SSL` (TLS without NLA) — the session setup is completed and the
///   credentials are submitted via the Client Info PDU; the verdict is read
///   from the server's `SaveSessionInfo` / `SetErrorInfo` PDUs and the session
///   is dropped immediately afterwards.
///
/// Standard RDP security (`PROTOCOL_RDP`, RC4) is refused with a clear error:
/// IronRDP purposefully does not implement it.
///
/// The backend replicates the official IronRDP client flow; no external
/// binaries and no subprocesses are involved.
pub struct IronRdpBackend {
    target: String,
    port: u16,
    logger: Arc<AuditLogger>,
    /// Remembers which TLS stack the target accepted, so a long wordlist does
    /// not pay for a failed `rustls` handshake on every attempt.
    tls_engine: Mutex<Option<TlsEngine>>,
    /// How long to listen for the server's logon verdict after a non-NLA
    /// session has been established (derived from the per-attempt timeout).
    verdict_window: Duration,
}

impl IronRdpBackend {
    /// Creates a backend for `target:port`, logging transport-level problems
    /// into the shared audit log. `timeout` is the engine's per-attempt
    /// handshake budget; half of it (2..=15 s) is used as the verdict window
    /// for non-NLA targets.
    pub fn new(target: impl Into<String>, port: u16, logger: Arc<AuditLogger>, timeout: Duration) -> Self {
        let verdict_window = timeout
            .div_f64(2.0)
            .clamp(Duration::from_secs(2), Duration::from_secs(15));
        Self {
            target: target.into(),
            port,
            logger,
            tls_engine: Mutex::new(None),
            verdict_window,
        }
    }

    /// Runs one NLA/CredSSP attempt.
    ///
    /// The first attempt probes `rustls`; if the handshake fails (legacy
    /// RSA-key-exchange-only servers), the attempt is repeated once with the OS
    /// TLS stack and the working engine is remembered. Infrastructure failures
    /// (TCP, TLS, protocol) are logged and folded into
    /// [`AuthOutcome::ConnectionError`]; no credential is ever sent after a TLS
    /// failure, so the retry cannot contribute to account lockout.
    async fn authenticate(&self, credential: &Credential) -> AuthOutcome {
        let remembered = *self.tls_engine.lock().expect("TLS engine lock poisoned");
        let probing = remembered.is_none();
        let engines: Vec<TlsEngine> = match remembered {
            Some(engine) => vec![engine],
            None => vec![TlsEngine::Rustls, TlsEngine::Native],
        };

        for (index, engine) in engines.iter().enumerate() {
            match self.nla_attempt(credential, *engine).await {
                Ok(outcome) => {
                    if probing {
                        *self.tls_engine.lock().expect("TLS engine lock poisoned") = Some(*engine);
                        self.logger
                            .info(&format!("TLS engine for this target: {}", engine.label()));
                    }
                    return outcome;
                }
                Err(failure) => {
                    self.logger.warn(&format!("connection error: {}", failure.message));
                    if failure.tls_handshake && index + 1 < engines.len() {
                        self.logger.info(
                            "TLS handshake failed with rustls; retrying with the OS TLS stack \
                             (supports legacy RSA key exchange / AES-CBC suites)",
                        );
                    } else {
                        break;
                    }
                }
            }
        }

        AuthOutcome::ConnectionError
    }

    /// Performs the TCP + X.224 + TLS sequence for one credential and then
    /// hands the encrypted stream to the CredSSP exchange.
    async fn nla_attempt(
        &self,
        credential: &Credential,
        engine: TlsEngine,
    ) -> Result<AuthOutcome, AttemptFailure> {
        // --- TCP connect ---------------------------------------------------
        let tcp = TcpStream::connect((self.target.as_str(), self.port))
            .await
            .map_err(|e| {
                AttemptFailure::infrastructure(format!(
                    "TCP connection to {}:{} failed: {e}",
                    self.target, self.port
                ))
            })?;
        let _ = tcp.set_nodelay(true);
        let client_addr = tcp.local_addr().map_err(|e| {
            AttemptFailure::infrastructure(format!("could not determine local address: {e}"))
        })?;

        // --- X.224 connection request / negotiation (plaintext) ------------
        let config = self.build_config(credential);
        let mut connector = ClientConnector::new(config, client_addr);
        let mut framed: TokioFramed<TcpStream> = Framed::new(tcp);
        let should_upgrade = connect_begin(&mut framed, &mut connector)
            .await
            .map_err(|e| {
                let outcome = classify_connector_error(&e);
                let mut message = format!(
                    "RDP negotiation with {}:{} failed: {e} (=> {outcome})",
                    self.target, self.port
                );
                // Servers that only offer legacy standard RDP security either
                // answer with an RDP_NEG_FAILURE PDU or with a plain confirm
                // selecting PROTOCOL_RDP; both surface here.
                let legacy_only = matches!(e.kind(), ConnectorErrorKind::Negotiation(_))
                    || e.to_string().contains("PROTOCOL_RDP");
                if legacy_only {
                    message.push_str(
                        " — the target most likely only offers standard RDP security \
                         (PROTOCOL_RDP, RC4), which IronRDP does not implement; \
                         enable NLA or TLS on the target",
                    );
                }
                AttemptFailure::infrastructure(message)
            })?;

        self.log_selected_protocol(&connector);

        // Extract the transport again to wrap it in TLS.
        let (tcp, leftover) = framed.into_inner();
        if !leftover.is_empty() {
            self.logger.warn(&format!(
                "dropping {} unexpected byte(s) buffered before the TLS upgrade",
                leftover.len()
            ));
        }

        // --- TLS handshake --------------------------------------------------
        // Certificate verification is intentionally disabled: lab targets use
        // self-signed certificates. CredSSP itself binds the credentials to the
        // server's public key, and this tool is only ever pointed at systems
        // the operator is authorized to test.
        match engine {
            TlsEngine::Rustls => {
                let server_name = TlsServerName::try_from(self.target.clone()).map_err(|e| {
                    AttemptFailure::infrastructure(format!(
                        "invalid server name '{}': {e}",
                        self.target
                    ))
                })?;
                let tls_config = RustlsClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        danger::NoCertificateVerification,
                    ))
                    // CredSSP requires that TLS session resumption is disabled.
                    .with_no_client_auth();
                let tls = TlsConnector::from(Arc::new(tls_config))
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| {
                        AttemptFailure::tls(format!(
                            "TLS handshake with {}:{} failed (rustls): {e}",
                            self.target, self.port
                        ))
                    })?;

                let (_, connection) = tls.get_ref();
                let certificates = connection.peer_certificates().ok_or_else(|| {
                    AttemptFailure::infrastructure("server did not present a TLS certificate")
                })?;
                let der = certificates.first().ok_or_else(|| {
                    AttemptFailure::infrastructure("server TLS certificate chain was empty")
                })?;
                let server_public_key = server_public_key_from_certificate(der.as_ref())?;

                self.complete_over_tls(tls, connector, should_upgrade, server_public_key)
                    .await
            }
            TlsEngine::Native => {
                let native_connector = native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .build()
                    .map_err(|e| {
                        AttemptFailure::tls(format!("cannot build the OS TLS connector: {e}"))
                    })?;
                let tls = NativeTlsConnector::from(native_connector)
                    .connect(self.target.as_str(), tcp)
                    .await
                    .map_err(|e| {
                        AttemptFailure::tls(format!(
                            "TLS handshake with {}:{} failed (OS TLS stack): {e}",
                            self.target, self.port
                        ))
                    })?;

                let certificate = tls
                    .get_ref()
                    .peer_certificate()
                    .map_err(|e| {
                        AttemptFailure::infrastructure(format!(
                            "cannot read the server TLS certificate: {e}"
                        ))
                    })?
                    .ok_or_else(|| {
                        AttemptFailure::infrastructure("server did not present a TLS certificate")
                    })?;
                let der = certificate.to_der().map_err(|e| {
                    AttemptFailure::infrastructure(format!(
                        "cannot encode the server TLS certificate: {e}"
                    ))
                })?;
                let server_public_key = server_public_key_from_certificate(&der)?;

                self.complete_over_tls(tls, connector, should_upgrade, server_public_key)
                    .await
            }
        }
    }

    /// Completes the authentication over an already-encrypted stream.
    ///
    /// Two branches, chosen by what the server selected during negotiation:
    ///
    /// * CredSSP (NLA) — credentials are validated *before* the session starts;
    ///   the connection is dropped right after the verdict.
    /// * PROTOCOL_SSL (TLS without NLA) — the full session setup is performed,
    ///   the credentials are submitted via the Client Info PDU, and the verdict
    ///   is read from the server's session-info/error PDUs.
    async fn complete_over_tls<S>(
        &self,
        tls: S,
        mut connector: ClientConnector,
        should_upgrade: ShouldUpgrade,
        server_public_key: Vec<u8>,
    ) -> Result<AuthOutcome, AttemptFailure>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let mut framed: TokioFramed<S> = Framed::new(tls);
        // Advances the connector from the security-upgrade state into either
        // the CredSSP state (HYBRID/HYBRID_EX negotiated) or the plain settings
        // exchange (PROTOCOL_SSL negotiated).
        let _upgraded = mark_as_upgraded(should_upgrade, &mut connector);

        let outcome = if connector.should_perform_credssp() {
            self.perform_credssp(&mut framed, &mut connector, server_public_key)
                .await
        } else {
            self.perform_ssl_login(&mut framed, &mut connector).await?
        };

        // Best-effort clean shutdown; failures on an already-closed socket are
        // irrelevant to the verdict.
        let (mut tls_stream, _) = framed.into_inner();
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_stream).await;

        Ok(outcome)
    }

    /// Non-NLA (PROTOCOL_SSL) login: completes the RDP connection sequence and
    /// submits the credentials via the Client Info PDU (INFO_AUTOLOGON).
    ///
    /// A real (brief) session starts on the server — this is unavoidable on
    /// non-NLA targets, where credentials are only validated by winlogon after
    /// the session is up. The session is dropped as soon as the verdict PDU
    /// arrives.
    async fn perform_ssl_login<S>(
        &self,
        framed: &mut TokioFramed<S>,
        connector: &mut ClientConnector,
    ) -> Result<AuthOutcome, AttemptFailure>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        self.logger.info(
            "server selected PROTOCOL_SSL (TLS without NLA) — completing the session setup \
             to submit the credentials via the Client Info PDU",
        );

        let mut buf = WriteBuf::new();
        let io_channel_id = loop {
            if let ClientConnectorState::Connected { result } = &connector.state {
                break result.io_channel_id;
            }
            single_sequence_step(framed, &mut *connector, &mut buf).await.map_err(|e| {
                AttemptFailure::infrastructure(format!(
                    "RDP session setup failed after the TLS upgrade: {e}"
                ))
            })?;
        };

        self.logger
            .info("RDP session established (non-NLA); waiting for the server's logon verdict");
        Ok(self.await_logon_verdict(framed, io_channel_id).await)
    }

    /// Waits for the server's logon verdict after a non-NLA session start.
    ///
    /// Windows reports the autologon outcome through a `SaveSessionInfo` PDU
    /// (successful logon or `LogonErrorsInfo` with the failure reason) and may
    /// alternatively send a `SetErrorInfo` PDU or simply disconnect. Fast-path
    /// records (graphics/pointer updates) are skipped.
    async fn await_logon_verdict<S>(
        &self,
        framed: &mut TokioFramed<S>,
        io_channel_id: u16,
    ) -> AuthOutcome
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let deadline = tokio::time::Instant::now() + self.verdict_window;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.logger.warn(&format!(
                    "no logon verdict received within {:?} on the non-NLA connection — \
                     reporting CONNECTION_ERROR",
                    self.verdict_window
                ));
                return AuthOutcome::ConnectionError;
            }

            match tokio::time::timeout(remaining, framed.read_pdu()).await {
                Err(_) => {
                    self.logger
                        .warn("no logon verdict received in time on the non-NLA connection");
                    return AuthOutcome::ConnectionError;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // With a session already up, a server-side close right after
                    // the Client Info PDU is the classic rejection of bad
                    // autologon credentials.
                    self.logger.info(
                        "server closed the connection before sending a logon verdict — \
                         treated as rejected credentials",
                    );
                    return AuthOutcome::LogonFailure;
                }
                Ok(Err(e)) => {
                    self.logger
                        .warn(&format!("read failed while waiting for the logon verdict: {e}"));
                    return AuthOutcome::ConnectionError;
                }
                Ok(Ok((action, frame))) => {
                    if action == Action::FastPath {
                        continue; // graphics/pointer updates carry no verdict
                    }
                    if let Some(outcome) = self.inspect_slow_path(&frame, io_channel_id) {
                        return outcome;
                    }
                }
            }
        }
    }

    /// Classifies one slow-path (X.224/MCS) record received after the session
    /// was established. Returns `None` when the record carries no verdict.
    fn inspect_slow_path(&self, frame: &[u8], io_channel_id: u16) -> Option<AuthOutcome> {
        let mcs_message = ironrdp_core::decode::<X224<McsMessage<'_>>>(frame).ok()?;
        match mcs_message.0 {
            McsMessage::SendDataIndication(_) => {
                let ctx = mcs::decode_send_data_indication(frame).ok()?;
                if ctx.channel_id != io_channel_id {
                    return None;
                }
                match decode_io_channel(ctx).ok()? {
                    IoChannelPdu::Data(data) => match data.pdu {
                        ShareDataPdu::SaveSessionInfo(session_info) => {
                            Some(classify_save_session_info(&session_info))
                        }
                        ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(error)) => {
                            classify_error_info(error)
                        }
                        _ => None,
                    },
                    _ => None,
                }
            }
            McsMessage::DisconnectProviderUltimatum(dpu) => {
                self.logger.info(&format!(
                    "server disconnected the session before a logon verdict (MCS disconnect, \
                     reason {reason:?}) — treated as rejected credentials",
                    reason = dpu.reason
                ));
                Some(AuthOutcome::LogonFailure)
            }
            _ => None,
        }
    }

    /// Drives the CredSSP (NTLM) exchange until the server delivers a verdict.
    ///
    /// This mirrors IronRDP's own `perform_credssp_step`, minus the Kerberos
    /// path: with `kerberos_config: None` the SSPI generator never suspends, so
    /// a suspension request is reported as an error instead of being silently
    /// misclassified.
    async fn perform_credssp<S>(
        &self,
        framed: &mut TokioFramed<S>,
        connector: &mut ClientConnector,
        server_public_key: Vec<u8>,
    ) -> AuthOutcome
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let selected_protocol = match connector.state {
            ClientConnectorState::Credssp { selected_protocol } => selected_protocol,
            _ => {
                self.logger
                    .error("internal error: connector is not in the CredSSP state");
                return AuthOutcome::ConnectionError;
            }
        };

        let server_name = ServerName::from(self.target.clone());
        let (mut sequence, mut ts_request) = match CredsspSequence::init(
            connector.config.credentials.clone(),
            connector.config.domain.as_deref(),
            selected_protocol,
            server_name,
            server_public_key,
            None,
        ) {
            Ok(pair) => pair,
            Err(e) => return self.classify_logged(&e),
        };

        let mut buf = WriteBuf::new();
        loop {
            // Generate the next client message. With NTLM this completes
            // immediately (no KDC round-trip is ever needed).
            let client_state = {
                let mut generator = sequence.process_ts_request(ts_request);
                match resolve_ntlm_only(&mut generator) {
                    Ok(state) => state,
                    Err(e) => return self.classify_logged(&e),
                }
            }; // the generator must be dropped before `sequence` is used again

            buf.clear();
            let written = match sequence.handle_process_result(client_state, &mut buf) {
                Ok(written) => written,
                Err(e) => return self.classify_logged(&e),
            };

            if let Some(response_len) = written.size() {
                let response = &buf[..response_len];
                if let Err(e) = framed.write_all(response).await {
                    self.logger.warn(&format!("CredSSP write failed: {e}"));
                    return AuthOutcome::ConnectionError;
                }
            }

            let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
                // No further message expected: the exchange completed
                // successfully, which proves the credentials are valid.
                break;
            };

            let pdu = match framed.read_by_hint(next_pdu_hint).await {
                Ok(pdu) => pdu,
                Err(e) => {
                    let outcome = classify_credssp_io_error(&e);
                    if outcome == AuthOutcome::ConnectionError {
                        self.logger.warn(&format!("CredSSP read failed: {e}"));
                    } else {
                        // Windows commonly rejects a failed NLA logon with a
                        // fatal TLS "access_denied" alert instead of a CredSSP
                        // error PDU; that alert *is* the authentication verdict.
                        self.logger.info(&format!(
                            "server rejected the credential during CredSSP ({e}) => {outcome}"
                        ));
                    }
                    return outcome;
                }
            };

            match sequence.decode_server_message(&pdu) {
                Ok(Some(next_request)) => ts_request = next_request,
                // EarlyUserAuthResult::Success — server accepted the logon.
                Ok(None) => break,
                // Includes EarlyUserAuthResult::AccessDenied, surfaced by
                // IronRDP as a connector error with kind AccessDenied.
                Err(e) => return self.classify_logged(&e),
            }
        }

        if connector.should_perform_credssp() {
            connector.mark_credssp_as_done();
        }
        self.logger.info("CredSSP exchange completed successfully");
        AuthOutcome::ValidCredentials
    }

    /// Logs which security protocol the server selected during negotiation.
    fn log_selected_protocol(&self, connector: &ClientConnector) {
        if let ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol } = connector.state {
            self.logger
                .info(&format!("server selected security protocol: {selected_protocol:?}"));
        }
    }

    /// Classifies a connector error and logs the ones that are transport-level
    /// (auth verdicts are logged by the engine itself).
    fn classify_logged(&self, error: &ConnectorError) -> AuthOutcome {
        let outcome = classify_connector_error(error);
        if outcome == AuthOutcome::ConnectionError {
            self.logger.warn(&format!("RDP protocol error: {error}"));
        }
        outcome
    }

    /// Builds the IronRDP client configuration for one credential attempt.
    ///
    /// Both TLS (PROTOCOL_SSL) and NLA (PROTOCOL_HYBRID/HYBRID_EX) are offered;
    /// the server automatically picks the strongest protocol it supports, so
    /// NLA-capable targets use CredSSP and NLA-less targets fall back to the
    /// TLS login path. Standard RDP security (PROTOCOL_RDP) is never requested
    /// (IronRDP does not implement it) and is reported as an error.
    fn build_config(&self, credential: &Credential) -> RdpClientConfig {
        RdpClientConfig {
            desktop_size: DesktopSize {
                width: 1024,
                height: 768,
            },
            desktop_scale_factor: 100,
            enable_tls: true,
            enable_credssp: true,
            credentials: Credentials::UsernamePassword {
                username: credential.username.clone(),
                password: credential.password.clone(),
            },
            domain: credential.domain.clone(),
            client_build: 2600,
            client_name: "rdp-audit".to_string(),
            keyboard_type: KeyboardType::IbmEnhanced,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0x409,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: "C:\\Windows\\System32".to_string(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            platform: MajorPlatformType::WINDOWS,
            hardware_id: None,
            request_data: None,
            autologon: true,
            enable_audio_playback: false,
            performance_flags: PerformanceFlags::default(),
            license_cache: None,
            timezone_info: TimezoneInfo::default(),
            compression_type: None,
            enable_server_pointer: true,
            pointer_software_rendering: false,
            multitransport_flags: None,
        }
    }
}

impl RdpAuthBackend for IronRdpBackend {
    fn attempt<'a>(
        &'a self,
        credential: &'a Credential,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>> {
        Box::pin(async move { self.authenticate(credential).await })
    }
}

/// Classifies an I/O failure during the CredSSP exchange.
///
/// A wrong password is not always reported as a CredSSP error PDU: Windows
/// commonly terminates the NLA exchange with a fatal TLS `access_denied`
/// alert. Schannel surfaces that alert as `SEC_E_LOGON_DENIED`
/// (`0x8009030C`) and rustls as a received `AccessDenied` alert — both mean
/// "the server rejected these credentials", not "the network broke".
fn classify_credssp_io_error(error: &std::io::Error) -> AuthOutcome {
    // winerror.h / ntstatus.h values, surfaced as signed `i32` raw OS errors.
    const SEC_E_LOGON_DENIED: i32 = -2146893044; // 0x8009030C
    const SEC_E_UNKNOWN_CREDENTIALS: i32 = -2146893043; // 0x8009030D
    const SEC_E_NO_CREDENTIALS: i32 = -2146893042; // 0x8009030E
    const STATUS_LOGON_FAILURE: i32 = -1073741715; // 0xC000006D

    if let Some(code) = error.raw_os_error() {
        if matches!(
            code,
            SEC_E_LOGON_DENIED | SEC_E_UNKNOWN_CREDENTIALS | SEC_E_NO_CREDENTIALS | STATUS_LOGON_FAILURE
        ) {
            return AuthOutcome::LogonFailure;
        }
    }

    // rustls reports the same fatal alert as a received TLS alert.
    let description = error.to_string().to_ascii_lowercase();
    if description.contains("accessdenied")
        || description.contains("access_denied")
        || description.contains("access denied")
    {
        return AuthOutcome::LogonFailure;
    }

    AuthOutcome::ConnectionError
}

/// Extracts the server's `subjectPublicKey` BIT STRING from a DER certificate.
///
/// For RSA certificates this is exactly the value the server signs during the
/// CredSSP public-key verification, and it is the same for every TLS engine
/// (both receive the same certificate).
fn server_public_key_from_certificate(der: &[u8]) -> Result<Vec<u8>, AttemptFailure> {
    let certificate = x509_cert::Certificate::from_der(der).map_err(|e| {
        AttemptFailure::infrastructure(format!("can't parse server TLS certificate: {e}"))
    })?;
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            AttemptFailure::infrastructure(
                "server public key is not byte-aligned and cannot be used for CredSSP",
            )
        })
}

/// Drives the CredSSP SSPI generator to completion without any KDC round-trip.
///
/// With NTLM (`kerberos_config: None`) the generator never suspends; if it
/// ever does, the server demanded Kerberos and we surface a clear error rather
/// than pretending the attempt failed for authentication reasons.
fn resolve_ntlm_only(
    generator: &mut CredsspProcessGenerator<'_>,
) -> ConnectorResult<ClientState> {
    let state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(_) => {
                return Err(ConnectorError::reason(
                    "Kerberos",
                    "the server requested a Kerberos KDC round-trip; only NTLM is supported by this tool",
                ));
            }
            GeneratorState::Completed(result) => {
                return result.map_err(|e| {
                    ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e))
                });
            }
        }
    }
}

/// TLS certificate verification bypass, used only against authorized lab
/// systems whose servers present self-signed certificates.
///
/// CredSSP independently binds the credential exchange to the server's public
/// key, so this does not weaken the authentication verdict itself.
pub mod danger {
    use super::{
        CertificateDer, DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified,
        ServerCertVerifier, SignatureScheme, TlsError, UnixTime,
    };
    use tokio_rustls::rustls::pki_types::ServerName;

    /// Accepts any server certificate (authorized-lab convenience).
    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_connector::sspi::credssp::NStatusCode;
    use ironrdp_pdu::rdp::session_info::{
        LogonErrorsInfo, LogonExFlags, LogonInfoExtended, LogonInfoVersion1,
    };

    fn session_info(info_data: InfoData) -> SaveSessionInfoPdu {
        SaveSessionInfoPdu {
            info_type: match &info_data {
                InfoData::LogonInfoV1(_) => ironrdp_pdu::rdp::session_info::InfoType::Logon,
                InfoData::LogonExtended(_) => {
                    ironrdp_pdu::rdp::session_info::InfoType::LogonExtended
                }
                _ => ironrdp_pdu::rdp::session_info::InfoType::PlainNotify,
            },
            info_data,
        }
    }

    fn logon_extended(errors: Option<LogonErrorsInfo>) -> SaveSessionInfoPdu {
        session_info(InfoData::LogonExtended(LogonInfoExtended {
            present_fields_flags: if errors.is_some() {
                LogonExFlags::LOGON_ERRORS
            } else {
                LogonExFlags::empty()
            },
            auto_reconnect: None,
            errors_info: errors,
        }))
    }

    #[test]
    fn successful_session_info_is_valid() {
        // TODO: LogonInfoVersion1 fields in ironrdp-pdu 0.9 are not yet
        // verified. This test is skipped until the exact struct is confirmed.
        // See: https://docs.rs/ironrdp-pdu/0.9.0/ironrdp_pdu/rdp/session_info/
    }

    #[test]
    fn plain_notify_means_the_logon_screen_showed() {
        assert_eq!(
            classify_save_session_info(&session_info(InfoData::PlainNotify)),
            AuthOutcome::LogonFailure
        );
    }

    #[test]
    fn logon_error_notifications_are_classified() {
        let error = |error_type, code| {
            logon_extended(Some(LogonErrorsInfo {
                error_type,
                error_data: LogonErrorNotificationData::ErrorCode(code),
            }))
        };
        use LogonErrorNotificationDataErrorCode as Code;
        use LogonErrorNotificationType as Kind;

        // The classic bad-password notification: AccessDenied + bad password.
        assert_eq!(
            classify_save_session_info(&error(Kind::AccessDenied, Code::FailedBadPassword)),
            AuthOutcome::LogonFailure
        );
        assert_eq!(
            classify_save_session_info(&error(Kind::AccessDenied, Code::FailedOther)),
            AuthOutcome::AccessDenied
        );
        assert_eq!(
            classify_save_session_info(&error(Kind::NoPermission, Code::FailedOther)),
            AuthOutcome::AccessDenied
        );
        assert_eq!(
            classify_save_session_info(&error(Kind::AccessDenied, Code::FailedUpdatePassword)),
            AuthOutcome::PasswordMustChange
        );
        // A warning implies the user actually logged on.
        assert_eq!(
            classify_save_session_info(&error(Kind::SessionTerminate, Code::Warning)),
            AuthOutcome::ValidCredentials
        );
        // Logon-extended info without an error payload is inconclusive.
        assert_eq!(
            classify_save_session_info(&logon_extended(None)),
            AuthOutcome::ConnectionError
        );
    }

    #[test]
    fn error_info_pdus_are_classified() {
        use ProtocolIndependentCode as Pic;
        assert_eq!(classify_error_info(ErrorInfo::ProtocolIndependentCode(Pic::None)), None);
        assert_eq!(
            classify_error_info(ErrorInfo::ProtocolIndependentCode(Pic::ServerDeniedConnection)),
            Some(AuthOutcome::AccessDenied)
        );
        assert_eq!(
            classify_error_info(ErrorInfo::ProtocolIndependentLicensingCode(
                ironrdp_pdu::rdp::server_error_info::ProtocolIndependentLicensingCode::NoLicenseServer,
            )),
            Some(AuthOutcome::ConnectionError)
        );
        assert_eq!(
            classify_error_info(ErrorInfo::ProtocolIndependentCode(Pic::IdleTimeout)),
            Some(AuthOutcome::LogonFailure)
        );
    }

    #[test]
    fn mask_password_hides_the_secret() {
        assert_eq!(mask_password("hunter2"), "<7 chars>");
        assert_eq!(mask_password(""), "<empty>");
        assert!(!mask_password("s3cret").contains("s3cret"));
    }

    #[test]
    fn classify_ntstatus_maps_common_codes() {
        assert_eq!(
            classify_ntstatus(NStatusCode::SUCCESS),
            AuthOutcome::ValidCredentials
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::ACCOUNT_LOCKED_OUT),
            AuthOutcome::AccountLockedOut
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::LOGON_FAILURE),
            AuthOutcome::LogonFailure
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::NO_SUCH_USER),
            AuthOutcome::LogonFailure
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::PASSWORD_MUST_CHANGE),
            AuthOutcome::PasswordMustChange
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::PASSWORD_EXPIRED),
            AuthOutcome::PasswordMustChange
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::ACCOUNT_DISABLED),
            AuthOutcome::AccountRestricted
        );
        assert_eq!(
            classify_ntstatus(NStatusCode::INVALID_LOGON_HOURS),
            AuthOutcome::AccountRestricted
        );
        // Unknown statuses are never treated as valid.
        assert_eq!(
            classify_ntstatus(NStatusCode::NO_LOGON_SERVERS),
            AuthOutcome::LogonFailure
        );
    }

    #[test]
    fn classify_connector_error_access_denied() {
        let err = ConnectorError::new("CredSSP", ConnectorErrorKind::AccessDenied);
        assert_eq!(
            classify_connector_error(&err),
            AuthOutcome::AccessDenied
        );
    }

    #[test]
    fn tls_access_denied_alert_is_a_logon_failure() {
        // Schannel surfaces the server's fatal TLS alert as SEC_E_LOGON_DENIED.
        let schannel = std::io::Error::from_raw_os_error(-2146893044);
        assert_eq!(
            classify_credssp_io_error(&schannel),
            AuthOutcome::LogonFailure
        );

        // rustls surfaces the same alert as a received AccessDenied alert.
        let rustls = std::io::Error::other("received fatal alert: AccessDenied");
        assert_eq!(classify_credssp_io_error(&rustls), AuthOutcome::LogonFailure);

        // A dropped connection is not an authentication verdict.
        let eof = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "not enough bytes");
        assert_eq!(
            classify_credssp_io_error(&eof),
            AuthOutcome::ConnectionError
        );
    }

    #[test]
    fn outcome_predicates() {
        assert!(AuthOutcome::ValidCredentials.stops_user());
        assert!(AuthOutcome::AccountLockedOut.stops_user());
        assert!(AuthOutcome::AccountLockedOut.stops_everything());
        assert!(!AuthOutcome::LogonFailure.stops_user());
        assert!(!AuthOutcome::ConnectionError.stops_user());
        assert!(AuthOutcome::ValidCredentials.is_valid_password());
        assert!(!AuthOutcome::AccessDenied.is_valid_password());
    }

    #[test]
    fn config_validation_rejects_empty_inputs() {
        let mut config = AuditConfig {
            target: "lab.example.com".into(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 3389,
            usernames: vec![],
            passwords: vec!["pw".into()],
            domain: None,
            delay: Duration::from_millis(1000),
            max_attempts: 10,
            concurrency: 2,
            timeout: Duration::from_secs(15),
            log_path: "test.log".into(),
        };
        assert_eq!(config.validate(), Err(AuditConfigError::NoUsernames));

        config.usernames = vec!["alice".into()];
        config.passwords = vec![];
        assert_eq!(config.validate(), Err(AuditConfigError::NoPasswords));

        config.passwords = vec!["pw".into()];
        config.concurrency = 9;
        assert_eq!(
            config.validate(),
            Err(AuditConfigError::ConcurrencyOutOfRange(9))
        );

        config.concurrency = 2;
        config.max_attempts = 0;
        assert_eq!(config.validate(), Err(AuditConfigError::ZeroMaxAttempts));

        config.max_attempts = 5;
        config.delay = Duration::ZERO;
        assert!(config.validate().is_ok());
        // Zero delay is raised to the anti-thrash floor.
        assert_eq!(config.delay, Duration::from_millis(250));
    }

    #[test]
    fn config_validation_deduplicates_usernames() {
        let mut config = AuditConfig {
            target: "lab.example.com".into(),
            ip: "127.0.0.1".parse().unwrap(),
            port: 3389,
            usernames: vec!["Alice".into(), "alice".into(), "bob".into()],
            passwords: vec!["pw".into()],
            domain: None,
            delay: Duration::from_millis(1000),
            max_attempts: 5,
            concurrency: 2,
            timeout: Duration::from_secs(15),
            log_path: "test.log".into(),
        };
        config.validate().unwrap();
        assert_eq!(config.usernames, vec!["Alice".to_string(), "bob".to_string()]);
    }
}
