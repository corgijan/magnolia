use std::future::Future;
use std::time::Duration;

/// Runs `pass` in a burst-then-backoff loop — shared by every periodic
/// background job in this crate (dtrack/reputation/malicious/freshness
/// sync). Each `pass` call is one bounded batch (see each job's own
/// `BATCH_SIZE`/`LIMIT`); this drives *when* the next batch runs:
///
/// - `pass` returned `> 0` (it actually processed something): wait only
///   `burst_interval` before running the next batch. This is what lets a
///   large backlog — a bulk import, or the first run after this job shipped
///   against an existing archive — drain in a tight loop instead of one
///   bounded batch per hour.
/// - `pass` returned `0` (nothing left to do, *or* every item in the batch
///   failed): back off to the full `interval` before trying again. Every
///   job's own `pass`/`sync_pass` only counts genuine successes toward its
///   return value (a per-item failure is logged and skipped, not counted),
///   so an upstream outage looks the same as an empty queue here — both
///   correctly stop the burst instead of hammering a downed API every
///   `burst_interval`.
///
/// The very first `pass` runs immediately at startup, matching
/// `tokio::time::interval`'s own "first tick fires immediately" behavior
/// (what every caller here used before switching to this loop).
pub async fn run_burst_loop<F, Fut>(interval: Duration, burst_interval: Duration, mut pass: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = usize>,
{
    loop {
        let processed = pass().await;
        tokio::time::sleep(next_delay(processed, interval, burst_interval)).await;
    }
}

/// The actual burst-vs-backoff decision, pulled out of the loop above so
/// it's testable without needing to drive a `loop {}` that never returns.
/// Pure/no I/O.
fn next_delay(processed: usize, interval: Duration, burst_interval: Duration) -> Duration {
    if processed > 0 {
        burst_interval
    } else {
        interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursts_when_the_last_batch_processed_something() {
        let interval = Duration::from_secs(3600);
        let burst_interval = Duration::from_secs(30);
        assert_eq!(next_delay(1, interval, burst_interval), burst_interval);
        assert_eq!(next_delay(20, interval, burst_interval), burst_interval);
    }

    #[test]
    fn backs_off_to_the_full_interval_when_the_last_batch_processed_nothing() {
        let interval = Duration::from_secs(3600);
        let burst_interval = Duration::from_secs(30);
        // Covers both cases that yield 0: an empty queue, and a queue where
        // every item's attempt failed (a job's own `sync_pass` only counts
        // genuine successes) -- `next_delay` can't tell them apart, and
        // shouldn't need to: both should back off the same way.
        assert_eq!(next_delay(0, interval, burst_interval), interval);
    }
}
