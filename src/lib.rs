//! `rdp-audit` — educational RDP/NLA (CredSSP) credential audit library.
//!
//! The crate is split into three layers:
//!
//! * [`safety`] — target classification and the private-network refusal gate.
//! * [`logger`] — timestamped, append-only file logging of every audited action.
//! * [`rdp_tester`] — the orchestration engine ([`rdp_tester::RdpTester`]), the
//!   classification taxonomy ([`rdp_tester::AuthOutcome`]) and the real protocol
//!   backend ([`rdp_tester::IronRdpBackend`]) built on IronRDP.
//!
//! The protocol backend sits behind the [`rdp_tester::RdpAuthBackend`] trait so the
//! orchestration logic (lockout abort, attempt caps, per-user stops, rate limiting)
//! can be integration-tested with scripted mocks and **zero network traffic**.

pub mod logger;
pub mod rdp_tester;
pub mod safety;

pub use logger::AuditLogger;
pub use rdp_tester::{
    AuditConfig, AuditConfigError, AuditSummary, AttemptReport, AuthOutcome, Credential, HaltReason,
    IronRdpBackend, RdpAuthBackend, RdpTester, classify_connector_error, classify_ntstatus,
    mask_password,
};
pub use safety::{SafetyError, ensure_target_allowed, is_private_or_local_ip, resolve_target};
