use std::time::{SystemTime, UNIX_EPOCH};

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) fn current_timestamp() -> Result<String, String> {
    timestamp_at(OffsetDateTime::now_utc())
}

pub(crate) fn unix_nanos_id(prefix: &str) -> Result<String, String> {
    unix_nanos_id_at(prefix, SystemTime::now())
}

fn timestamp_at(timestamp: OffsetDateTime) -> Result<String, String> {
    timestamp
        .format(&Rfc3339)
        .map_err(|error| format!("current UTC timestamp could not be formatted: {error}"))
}

fn unix_nanos_id_at(prefix: &str, timestamp: SystemTime) -> Result<String, String> {
    let nanos = timestamp
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_nanos();
    Ok(format!("{prefix}-{nanos}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn identifiers_reject_pre_epoch_clocks_without_panicking() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("platform supports a pre-epoch test time");

        assert_eq!(
            unix_nanos_id_at("backup", before_epoch),
            Err("system clock is before the Unix epoch".to_string())
        );
    }

    #[test]
    fn timestamps_are_rfc3339() {
        let rendered = timestamp_at(OffsetDateTime::UNIX_EPOCH).expect("format timestamp");
        assert_eq!(rendered, "1970-01-01T00:00:00Z");
    }
}
