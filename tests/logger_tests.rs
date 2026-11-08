//! Tests for the audit logger's file format and semantics.

mod common;

use std::path::Path;

use common::temp_log_path;
use rdp_audit::AuditLogger;

#[test]
fn writes_one_timestamped_line_per_event() {
    let path = temp_log_path("logger");
    let logger = AuditLogger::create(&path).expect("create log file");

    logger.info("first line");
    logger.warn("second line");
    logger.error("third line");

    assert_eq!(logger.path(), Path::new(&path));

    let contents = std::fs::read_to_string(&path).expect("log readable");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 3, "one line per event");

    assert!(lines[0].contains("[INFO]") && lines[0].contains("first line"));
    assert!(lines[1].contains("[WARN]") && lines[1].contains("second line"));
    assert!(lines[2].contains("[ERROR]") && lines[2].contains("third line"));

    // RFC 3339 UTC timestamps with millisecond precision.
    for line in &lines {
        assert!(
            line.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "line must start with a timestamp: {line}"
        );
        assert!(
            line.contains("Z ["),
            "timestamp must be followed by a level marker: {line}"
        );
    }
}

#[test]
fn appends_across_logger_instances() {
    let path = temp_log_path("append");

    {
        let logger = AuditLogger::create(&path).expect("create");
        logger.info("run one");
    }
    {
        let logger = AuditLogger::create(&path).expect("re-open");
        logger.info("run two");
    }

    let contents = std::fs::read_to_string(&path).expect("log readable");
    assert!(contents.contains("run one"));
    assert!(contents.contains("run two"));
    assert_eq!(contents.lines().count(), 2);
}
