use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use magnolia_db::{Database, DueWebhookDelivery, WebhookEndpointRecord};
use sha2::Sha256;
use uuid::Uuid;

pub const EVENT_MANIFEST_UPLOADED: &str = "manifest.uploaded";
pub const EVENT_MANIFEST_REVOKED: &str = "manifest.revoked";
pub const EVENT_FINDING_NEW_CRITICAL: &str = "finding.new_critical";
pub const EVENT_MALICIOUS_MATCH_FOUND: &str = "malicious.match_found";
pub const EVENT_DTRACK_PUSH_FAILED: &str = "dtrack.push_failed";

/// Every event type a tenant can subscribe an endpoint to — the source of
/// truth for endpoint-creation validation and the frontend's event-type
/// checkboxes both read from, so adding a new event later means updating
/// exactly this list (plus the one `emit_event` call site for it).
pub const ALL_EVENT_TYPES: &[&str] = &[
    EVENT_MANIFEST_UPLOADED,
    EVENT_MANIFEST_REVOKED,
    EVENT_FINDING_NEW_CRITICAL,
    EVENT_MALICIOUS_MATCH_FOUND,
    EVENT_DTRACK_PUSH_FAILED,
];

/// Fans a new event out to every endpoint this tenant has subscribed to it
/// — writes one outbox row per matching endpoint (see
/// `webhook_deliveries`'s migration comment); never delivers synchronously
/// itself. Best-effort, same "secondary concern can't block/fail the
/// primary flow" idiom as `record_audit`/`dtrack_sync`: an enqueue failure
/// is logged, never propagated to the caller.
pub async fn emit_event(db: &Database, tenant_id: Uuid, event_type: &str, payload: serde_json::Value) {
    let endpoints = match db.list_enabled_webhook_endpoints_for_event(tenant_id, event_type).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(tenant_id = %tenant_id, event_type, error = %e, "webhooks: failed to list subscribed endpoints");
            return;
        }
    };
    for ep in endpoints {
        if let Err(e) = db.insert_webhook_delivery(ep.id, event_type, &payload).await {
            tracing::warn!(endpoint_id = %ep.id, event_type, error = %e, "webhooks: failed to enqueue delivery");
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 over the exact bytes sent, hex-encoded — the receiver
/// recomputes this the same way over the raw request body (not a
/// re-serialization of it, which could differ in field order/whitespace)
/// using the endpoint's own secret, to confirm the delivery actually came
/// from this deployment.
fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Rejects a webhook target that isn't a plain `http(s)` URL, or whose host
/// is a literal loopback/private/link-local/cloud-metadata IP address —
/// checked both when an endpoint is created/updated (reject a bad URL
/// outright, better UX than a silently-forever-failing delivery) and again
/// immediately before every delivery attempt (defense in depth against an
/// endpoint's URL having been valid at creation time and edited since —
/// there's no edit path today that skips this check, but a future one
/// easily could).
///
/// This does NOT resolve DNS — only a literal IP-address host is checked
/// against the disallowed ranges, so a hostname that *resolves* to a
/// private address (DNS rebinding) is not caught. A known, documented
/// limitation, not a complete SSRF mitigation — the same "best-effort,
/// re-verify before depending on this in production" caveat this codebase
/// already carries for its external-API client crates.
///
/// `allow_private` bypasses the private/loopback/metadata checks (never
/// the scheme check) — wired to `AppState::dev_mode` so local dev can point
/// a webhook at `http://localhost:...`; never set in production.
pub fn check_webhook_url(url: &str, allow_private: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("unsupported URL scheme '{other}' (use http or https)")),
    }
    if allow_private {
        return Ok(());
    }
    let host = parsed.host_str().ok_or_else(|| "URL has no host".to_string())?;
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err("localhost targets are not allowed".to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_disallowed_ip(&ip) {
            return Err(format!("target IP {ip} is not allowed (loopback/private/link-local/metadata)"));
        }
    }
    Ok(())
}

fn is_disallowed_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // The cloud instance-metadata endpoint (AWS/GCP/Azure all
                // use this exact address) — the canonical SSRF target, so
                // called out explicitly rather than left to rely on it
                // happening to be link-local (169.254.0.0/16 already covers
                // it, this is belt-and-suspenders documentation).
                || *v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 -- unique local addresses, IPv6's equivalent of
                // RFC-1918 private space.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Backoff schedule for a failed delivery: 1m, 5m, 30m, then 2h for every
/// attempt after that. `attempts` is the count *including* the attempt that
/// just failed (1-based). `None` once `attempts` reaches `MAX_ATTEMPTS` —
/// the delivery is given up on for good (`status = "failed"`), not
/// rescheduled.
const BACKOFF_SCHEDULE_MINUTES: [i64; 4] = [1, 5, 30, 120];
const MAX_ATTEMPTS: i32 = 8;

fn next_attempt_delay(attempts: i32) -> Option<chrono::Duration> {
    if attempts >= MAX_ATTEMPTS {
        return None;
    }
    let idx = ((attempts - 1).max(0) as usize).min(BACKOFF_SCHEDULE_MINUTES.len() - 1);
    Some(chrono::Duration::minutes(BACKOFF_SCHEDULE_MINUTES[idx]))
}

const DELIVERY_BATCH_SIZE: i64 = 50;

/// Periodic delivery worker — modeled on `dtrack_sync::run_sync_loop`'s
/// shape: poll a due-work queue, attempt each item, log-and-swallow every
/// per-item failure so a transient outage in one tenant's receiving server
/// never affects another delivery, let alone the loop itself.
pub async fn run_webhook_delivery_loop(db: Arc<Database>, interval: Duration, allow_private_targets: bool) {
    let http = reqwest::Client::new();
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        delivery_pass(&db, &http, allow_private_targets).await;
    }
}

/// One batch's worth of the delivery loop's work — same
/// periodic-loop/on-demand relationship as `dtrack_sync::sync_now`, though
/// nothing here currently exposes an on-demand "force delivery" endpoint
/// (unlike dtrack sync, an operator's actual lever for "deliver this now"
/// is the `/test` endpoint, which bypasses the outbox entirely — see
/// `send_test_event`). Returns how many deliveries succeeded this pass.
pub async fn delivery_pass(db: &Database, http: &reqwest::Client, allow_private_targets: bool) -> usize {
    let due = match db.list_due_webhook_deliveries(DELIVERY_BATCH_SIZE).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "webhooks: failed to list due deliveries");
            return 0;
        }
    };

    let mut delivered = 0;
    for d in due {
        if attempt_delivery(db, http, &d, allow_private_targets).await {
            delivered += 1;
        }
    }
    delivered
}

/// Sends one outbox row's payload, then records the outcome — `true` iff
/// the receiving server returned a 2xx. An SSRF-guard rejection is treated
/// as an immediate, unretryable failure (the target will never pass the
/// check on a later attempt), skipping the backoff schedule entirely rather
/// than burning through `MAX_ATTEMPTS` retries against a target that can
/// never succeed.
async fn attempt_delivery(
    db: &Database,
    http: &reqwest::Client,
    d: &DueWebhookDelivery,
    allow_private_targets: bool,
) -> bool {
    let attempts = d.attempts + 1;

    if let Err(reason) = check_webhook_url(&d.url, allow_private_targets) {
        if let Err(e) = db.record_webhook_delivery_failure(d.id, attempts, chrono::Utc::now(), "failed", &reason).await
        {
            tracing::warn!(delivery_id = d.id, error = %e, "webhooks: failed to record SSRF-guard rejection");
        }
        return false;
    }

    let body = match serde_json::to_vec(&d.payload) {
        Ok(b) => b,
        Err(e) => {
            if let Err(e2) =
                db.record_webhook_delivery_failure(d.id, attempts, chrono::Utc::now(), "failed", &e.to_string()).await
            {
                tracing::warn!(delivery_id = d.id, error = %e2, "webhooks: failed to record payload-encoding failure");
            }
            return false;
        }
    };
    let signature = sign(&d.secret, &body);
    let timestamp = chrono::Utc::now().timestamp();

    let result = http
        .post(&d.url)
        .header("Content-Type", "application/json")
        .header("X-Aise-Event", &d.event_type)
        .header("X-Aise-Timestamp", timestamp.to_string())
        .header("X-Aise-Signature", format!("sha256={signature}"))
        .timeout(Duration::from_secs(10))
        .body(body)
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            if let Err(e) = db.mark_webhook_delivery_delivered(d.id).await {
                tracing::warn!(delivery_id = d.id, error = %e, "webhooks: failed to mark delivery delivered");
            }
            true
        }
        Ok(resp) => {
            fail_and_reschedule(db, d.id, attempts, &format!("HTTP {}", resp.status().as_u16())).await;
            false
        }
        Err(e) => {
            fail_and_reschedule(db, d.id, attempts, &e.to_string()).await;
            false
        }
    }
}

async fn fail_and_reschedule(db: &Database, id: i64, attempts: i32, error: &str) {
    let (status, next_attempt_at) = match next_attempt_delay(attempts) {
        Some(delay) => ("pending", chrono::Utc::now() + delay),
        None => ("failed", chrono::Utc::now()),
    };
    if let Err(e) = db.record_webhook_delivery_failure(id, attempts, next_attempt_at, status, error).await {
        tracing::warn!(delivery_id = id, error = %e, "webhooks: failed to record delivery failure");
    }
}

/// Sends a one-off `webhook.test` event immediately, bypassing the outbox's
/// own polling delay entirely — the "Send test event" button's handler.
/// Still writes (and updates) a real `webhook_deliveries` row so the
/// attempt shows up in `GET /webhooks/{id}/deliveries` exactly like a real
/// event would, letting an operator confirm signature verification on
/// their receiving end without waiting for a real event to occur.
pub async fn send_test_event(
    db: &Database,
    http: &reqwest::Client,
    endpoint: &WebhookEndpointRecord,
    allow_private_targets: bool,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "event": "webhook.test",
        "endpoint_id": endpoint.id,
        "sent_at": chrono::Utc::now(),
    });
    let delivery_id =
        db.insert_webhook_delivery(endpoint.id, "webhook.test", &payload).await.map_err(|e| e.to_string())?;

    let due = DueWebhookDelivery {
        id: delivery_id,
        endpoint_id: endpoint.id,
        url: endpoint.url.clone(),
        secret: endpoint.secret.clone(),
        event_type: "webhook.test".to_string(),
        payload,
        attempts: 0,
    };
    if attempt_delivery(db, http, &due, allow_private_targets).await {
        Ok(())
    } else {
        Err("delivery failed — see this endpoint's deliveries for the specific error".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        assert!(check_webhook_url("ftp://example.com/hook", false).is_err());
        assert!(check_webhook_url("file:///etc/passwd", false).is_err());
    }

    #[test]
    fn rejects_loopback_and_private_targets_by_default() {
        assert!(check_webhook_url("http://127.0.0.1:8080/hook", false).is_err());
        assert!(check_webhook_url("http://localhost/hook", false).is_err());
        assert!(check_webhook_url("http://10.0.0.5/hook", false).is_err());
        assert!(check_webhook_url("http://192.168.1.1/hook", false).is_err());
        assert!(check_webhook_url("http://169.254.169.254/latest/meta-data", false).is_err());
    }

    #[test]
    fn allows_private_targets_when_flag_set() {
        assert!(check_webhook_url("http://127.0.0.1:8080/hook", true).is_ok());
        assert!(check_webhook_url("http://localhost/hook", true).is_ok());
    }

    #[test]
    fn allows_public_https_target() {
        assert!(check_webhook_url("https://example.com/webhooks/aise", false).is_ok());
    }

    #[test]
    fn rejects_malformed_url() {
        assert!(check_webhook_url("not a url", false).is_err());
    }

    #[test]
    fn signature_is_deterministic_and_key_sensitive() {
        let body = b"{\"hello\":\"world\"}";
        let sig_a = sign("secret-a", body);
        let sig_b = sign("secret-a", body);
        let sig_c = sign("secret-b", body);
        assert_eq!(sig_a, sig_b);
        assert_ne!(sig_a, sig_c);
        assert_eq!(sig_a.len(), 64); // 32-byte HMAC-SHA256, hex-encoded
    }

    #[test]
    fn backoff_schedule_follows_1_5_30_120_then_gives_up() {
        assert_eq!(next_attempt_delay(1), Some(chrono::Duration::minutes(1)));
        assert_eq!(next_attempt_delay(2), Some(chrono::Duration::minutes(5)));
        assert_eq!(next_attempt_delay(3), Some(chrono::Duration::minutes(30)));
        assert_eq!(next_attempt_delay(4), Some(chrono::Duration::minutes(120)));
        assert_eq!(next_attempt_delay(7), Some(chrono::Duration::minutes(120)));
        assert_eq!(next_attempt_delay(8), None);
        assert_eq!(next_attempt_delay(9), None);
    }
}
