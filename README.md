# rusthttp

Lightweight Rust HTTP client with Chrome TLS/HTTP2 fingerprint parity.

Bypasses Cloudflare, Akamai, DataDome via perfect TLS + HTTP/2 fingerprint matching.

## Features

- **Custom HTTP/2** — Chrome SETTINGS frame parity (`parts=3`), not using `h2` crate
- **BoringSSL TLS** — Chrome ClientHello (GREASE, X25519MLKEM768, extension permutation)
- **CONNECT Proxy** — rotating proxies with auth, correct SNI/verify through tunnel
- **Lightweight** — minimal dependencies, cross-platform (Linux/macOS/Windows/musl)

## Architecture

```
crates/
├── tls/      — BoringSSL wrapper, Chrome ClientHello config
├── h2/       — Custom HTTP/2 framing (Chrome SETTINGS parity)
├── proxy/    — HTTP CONNECT tunnel + auth + rotation
└── client/   — Public API (reqwest-like ergonomics)
```

## Target Fingerprint (Chrome 137+)

```
Akamai: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

## Usage

```rust
use rusthttp::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .chrome()
        .proxy("http://user:pass@host:port")
        .build()?;

    let resp = client.get("https://example.com").send().await?;
    println!("{}", resp.status());
    Ok(())
}
```

## Status

🚧 Work in progress — Phase 1 (TLS + HTTP/2 + Proxy MVP)

## License

MIT
