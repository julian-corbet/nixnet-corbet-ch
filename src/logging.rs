//! Minimal stderr logger mirroring the Go original's
//! `log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)`: one
//! "<date> <time> <message>" line per call, no other prefix, no other
//! sink. Timestamps are UTC rather than local time -- `time`'s local-offset
//! lookup is documented unsound to call from a process with more than one
//! thread (which this daemon always is, by design), and the log timestamp
//! zone is cosmetic/observability-only, not part of any wire contract or
//! test in this port.

use time::OffsetDateTime;

/// Renders "YYYY/MM/DD HH:MM:SS" for the current instant, UTC.
pub fn timestamp_prefix() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Writes one timestamped line to stderr, matching every `logger.Printf`
/// call site in the Go original.
#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => {
        eprintln!("{} {}", $crate::logging::timestamp_prefix(), format!($($arg)*))
    };
}
