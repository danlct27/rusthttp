# rusthttp — Project Proposal & Checkpoint Plan

> 基於 10-agent 3-round discussion 嘅 consensus。所有開發必須跟呢份 doc。

## 1. Project Identity

- **Name**: `rusthttp`
- **Repo**: `github.com/danlct27/rusthttp`
- **定位**: Lightweight anti-fingerprint HTTP client — Chrome TLS + HTTP/2 parity, from scratch
- **唔係 fork**: 唔 fork wreq / specters / reqwest / h2 / hyper

## 2. Architecture（Final — 4 Crate Workspace）

```
rusthttp/
├── Cargo.toml (workspace)
├── crates/
│   ├── tls/       # BoringSSL binding + Chrome ClientHello fingerprint
│   ├── h2/        # Custom HTTP/2 framing (唔用 h2 crate)
│   │   └── hpack/ # HPACK encoder/decoder (Chrome encoding style)
│   ├── proxy/     # HTTP CONNECT tunnel + TLS-in-TLS
│   └── client/    # Public API + cookie + redirect + profiles
├── profiles/      # Browser profile JSON files
│   ├── chrome137.json
│   ├── schema.json
│   └── CHANGELOG.md  # Provenance tracking (Chrome build + capture date)
├── tests/
│   └── fingerprint/  # Golden file comparison + external endpoint tests
└── scripts/
    └── capture-profile.py  # chrome://net-export/ → profile JSON generator
```

## 3. Target Fingerprint（Chrome 137+）

```
Akamai: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

- SETTINGS: 4 params only (HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE)
- WINDOW_UPDATE: 15663105 (connection-level)
- PRIORITY: 0 (Chrome uses RFC 9218 `priority: u=0, i` header)
- Pseudo-header order: `:method, :authority, :scheme, :path`

## 4. Function List & Phases

### Phase 1 — MVP（4-5 週）

| Category | Feature | Priority | Owner |
|----------|---------|----------|-------|
| TLS | Chrome ClientHello (JA3/JA4 parity) | P0 | Don |
| TLS | BoringSSL cert store + `danger_accept_invalid_certs` | P0 | Don |
| TLS | GREASE + extension permutation | P0 | Don |
| TLS | X25519MLKEM768 (post-quantum key exchange) | P0 | Don |
| TLS | Certificate compression (brotli) | P0 | Don |
| HTTP/2 | Chrome SETTINGS frame (exact order + values) | P0 | Kai |
| HTTP/2 | WINDOW_UPDATE (connection-level 15663105) | P0 | Kai |
| HTTP/2 | HPACK encoder (Chrome encoding style) | P0 | Tom |
| HTTP/2 | HPACK decoder | P0 | Tom |
| HTTP/2 | Stream state machine + flow control | P0 | Kai |
| HTTP/2 | PRIORITY frame (single deprecated frame) | P1 | Kai |
| Proxy | HTTP CONNECT tunnel establishment | P0 | Don |
| Proxy | TLS-in-TLS (SNI + verify = target hostname) | P0 | Don |
| Proxy | Basic auth (user:pass) | P0 | Don |
| Client | `Client::builder().chrome().proxy().build()` API | P0 | Don |
| Client | Single request (GET/POST + headers + body) | P0 | Don |
| Test | tls.peet.ws fingerprint assertion | P0 | Yuki |
| Test | Akamai H2 fingerprint assertion | P0 | Yuki |

**MVP Done = pass Akamai fingerprint + 1 CONNECT proxy + single request**
（冇 cookie、冇 redirect、冇 connection pool — 嗰啲 Phase 2）

### Phase 2（+2-3 週）

| Feature | Priority |
|---------|----------|
| Cookie jar (persistent) | P1 |
| Redirect following (301/302/307/308) | P1 |
| Connection pool (single origin) | P1 |
| Rotating proxy (round-robin + random) | P1 |
| Response streaming | P1 |
| Timeout (connect / read / total) | P1 |

### Phase 3（+2 週）

| Feature | Priority |
|---------|----------|
| HTTP/1.1 fallback (ALPN fail case) | P2 |
| WebSocket upgrade | P2 |
| Connection coalescing (RFC 7540 §9.1.1) | P2 |
| DoH resolver (optional feature flag) | P2 |
| Multi-profile rotation (per-request) | P2 |

## 5. Key Design Decisions（Consensus）

| Decision | Choice | Rationale |
|----------|--------|-----------|
| HTTP/2 implementation | From scratch (~1500 LoC client-only) | `h2` crate sends wrong SETTINGS; fork 比從頭寫更難 maintain |
| TLS library | `boring` crate (BoringSSL FFI) | Chrome 用 BoringSSL；`rustls` 唔支援 custom ClientHello |
| Profile format | JSON + `profiles/CHANGELOG.md` | chrome://net-export/ output 係 JSON；nested array 語法好過 TOML |
| DNS resolver | System resolver (MVP) | Akamai/Cloudflare 唔 fingerprint DNS；Phase 2 加 trait abstraction |
| HTTP/1.1 | Phase 3 | Target sites 全部 H2；ALPN fail 直接 error |
| Connection pool | Phase 2 | MVP = single connection；過早加 pool = debug 困難 |
| Error types | Per-crate enum + `#[from]` wrap | 唔用 `anyhow`；client crate 有 top-level `Error` |
| Concurrency | Single-threaded (tokio) | 唔用 `dashmap`；MVP 唔需要 shared pool |

## 6. Proxy Architecture（Fix specters bug 嘅 correct approach）

```
TCP connect → proxy_addr:port
  → Send: "CONNECT target.com:443 HTTP/1.1\r\nHost: target.com:443\r\n..."
  → Read: "HTTP/1.1 200 Connection Established\r\n\r\n"
  → TLS handshake on SAME socket:
      SSL_set_tlsext_host_name(ssl, "target.com")  // SNI = TARGET
      SSL_set1_host(ssl, "target.com")              // verify = TARGET
```

Key: After CONNECT, proxy is transparent. SNI + verify hostname MUST be TARGET (not proxy).

## 7. Testing Strategy

| Type | Tool | When |
|------|------|------|
| Unit tests | `cargo test` | Per-commit |
| Fingerprint regression | Local golden file (Chrome pcap byte diff) | Per-commit |
| External validation | tls.peet.ws + Akamai debug endpoint | Weekly scheduled CI |
| HPACK oracle | Compare against `h2` crate's decoder | Per-commit |

**Gate rule**: 冇 passing fingerprint assertion 唔好開下一個 phase。

## 8. Timeline & Checkpoints

| Week | Checkpoint | Done Means |
|------|-----------|------------|
| 1 | TLS layer compiles + connects to tls.peet.ws | JA4 hash matches Chrome 137 |
| 2 | HTTP/2 connection preface + SETTINGS sent correctly | Akamai fingerprint string = `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| 3 | HPACK encoder + HEADERS frame | Can send a GET request and receive response |
| 4 | CONNECT proxy + TLS-in-TLS | Request through proxy passes fingerprint check |
| 5 | Client API + integration test | `Client::builder().chrome().proxy(url).build()?.get(url).send().await` works end-to-end |
| 6-7 | Phase 2 (cookie, redirect, pool) | — |
| 8-9 | Phase 3 (H1 fallback, WebSocket) | — |

## 9. Dependencies（Minimal）

```toml
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
boring = "4"
boring-sys = "4"
tokio-boring = "4"
bytes = "1"
http = "1"
url = "2"
base64 = "0.22"
tracing = "0.1"
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**唔用**: hyper, h2, reqwest, rustls, dashmap, hickory-resolver, anyhow

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| BoringSSL cross-compile pain (cmake + Go) | CI 紅 | Pre-built binaries + CI matrix (Linux/macOS/Windows) |
| Chrome update breaks fingerprint (每 4 週) | Detection | Automated pcap capture pipeline (`scripts/capture-profile.py`) |
| HPACK encoding style fingerprinted by Akamai | Detection | Chrome pcap golden file byte-diff in CI |
| `boring` crate major version bump | Build break | Pin version, monitor releases |
| CONTINUATION frame edge case | Connection reset | Implement properly but Chrome rarely triggers it |
| ALPS (TLS-layer H2 SETTINGS) | Future detection vector | Stub in Phase 1, implement Phase 2 |

## 11. Day 1 Actions

1. ☐ Create GitHub repo (`danlct27/rusthttp`)
2. ☐ Push existing scaffold
3. ☐ Capture Chrome 137 pcap (`chrome://net-export/`) — golden file for CI
4. ☐ Verify: does Akamai check PRIORITY frames? (10 min experiment)
5. ☐ Start `crates/tls/` — BoringSSL connector with Chrome ClientHello

---

*Generated from 10-agent 3-round discussion, 2026-06-11. Last updated: 2026-06-11.*
