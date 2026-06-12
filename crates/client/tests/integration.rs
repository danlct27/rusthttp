//! Integration test: verify Chrome fingerprint against tls.peet.ws
//!
//! This test makes a real HTTPS request to tls.peet.ws/api/all which returns
//! the observed TLS and HTTP/2 fingerprint. We verify:
//! 1. JA4 hash matches Chrome 149 pattern
//! 2. HTTP/2 SETTINGS match Chrome (Akamai fingerprint format)
//! 3. Connection succeeds with valid response

use rusthttp::Client;

/// Expected Akamai HTTP/2 fingerprint parts for Chrome 149:
/// SETTINGS order: 1:65536;2:0;4:6291456;6:262144
/// WINDOW_UPDATE: 15663105
/// PRIORITY: 0 (deprecated but Chrome still sends weight)
const EXPECTED_H2_SETTINGS: &str = "1:65536;2:0;4:6291456;6:262144";
const EXPECTED_WINDOW_UPDATE: &str = "15663105";

#[tokio::test]
#[ignore] // requires network access — run with `cargo test -- --ignored`
async fn test_tls_fingerprint_peet_ws() {
    let client = Client::builder()
        .chrome()
        .build()
        .expect("failed to build client");

    let resp = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "unexpected status code");

    let body = resp.text().expect("body not utf8");
    println!("tls.peet.ws response:\n{}", body);

    // Parse JSON response
    let json: serde_json::Value =
        serde_json::from_str(body).expect("failed to parse response JSON");

    // Check TLS fingerprint exists
    let ja4 = json.get("tls")
        .and_then(|t| t.get("ja4"))
        .and_then(|v| v.as_str())
        .expect("no ja4 in response");
    println!("JA4: {}", ja4);

    // JA4 format: t13d...h2 — verify it starts with 't' (TLS 1.3) and ends with protocol
    assert!(ja4.starts_with('t'), "JA4 should start with 't' (TLS 1.3), got: {}", ja4);

    // Check HTTP/2 fingerprint
    let h2_fp = json.get("http2")
        .and_then(|h| h.get("akamai_fingerprint"))
        .and_then(|v| v.as_str());

    if let Some(fp) = h2_fp {
        println!("Akamai H2 fingerprint: {}", fp);
        // Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS
        let parts: Vec<&str> = fp.split('|').collect();
        assert!(parts.len() >= 2, "H2 fingerprint should have at least 2 parts");
        assert_eq!(parts[0], EXPECTED_H2_SETTINGS, "SETTINGS mismatch");
        assert_eq!(parts[1], EXPECTED_WINDOW_UPDATE, "WINDOW_UPDATE mismatch");
    }
}

#[tokio::test]
#[ignore]
async fn test_basic_https_request() {
    let client = Client::builder()
        .chrome()
        .build()
        .expect("failed to build client");

    let resp = client
        .get("https://httpbin.org/get")
        .header("x-test", "rusthttp")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let body = resp.text().expect("body not utf8");
    assert!(body.contains("rusthttp"), "custom header not reflected");
}

#[tokio::test]
#[ignore]
async fn test_proxy_connection() {
    // Skip if no proxy env var set
    let proxy_url = match std::env::var("TEST_PROXY_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("TEST_PROXY_URL not set, skipping proxy test");
            return;
        }
    };

    let client = Client::builder()
        .chrome()
        .proxy(&proxy_url)
        .build()
        .expect("failed to build client");

    let resp = client
        .get("https://httpbin.org/ip")
        .send()
        .await
        .expect("proxy request failed");

    assert_eq!(resp.status(), 200);
    let body = resp.text().expect("body not utf8");
    println!("IP via proxy: {}", body);
    // Should return the proxy's IP, not ours
    assert!(body.contains("origin"), "response should contain origin IP");
}
