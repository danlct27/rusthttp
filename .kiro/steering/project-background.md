---
name: project-background
inclusion: always
---

# rusthttp — Project Background

## 定位

Lightweight Rust HTTP client with Chrome TLS + HTTP/2 fingerprint parity。目標係 bypass Cloudflare/Akamai/DataDome bot detection。

**唔係** reqwest replacement。係 reqwest 做唔到嘅嘢（fingerprint spoofing）嘅補充。

## 點解要從頭寫

現有 library 嘅問題：
- `wreq` / `rquest`：TLS OK，但 HTTP/2 用 `h2` crate → SETTINGS frame 唔 match Chrome → 被 detect（`parts=4-6`）
- `specters`：HTTP/2 OK（`parts=3`），但冇 proxy support。Dan fork 加咗 proxy 但 cert verification bug 搞唔掂
- `reqwest`：冇 TLS fingerprint control

所以從零寫，唔 fork 任何人，每行 code 都有用。

## Architecture

```
rusthttp/
├── crates/
│   ├── rusthttp-tls/     # BoringSSL wrapper, Chrome ClientHello
│   ├── rusthttp-h2/      # Custom HTTP/2（唔用 h2 crate）
│   ├── rusthttp-proxy/   # CONNECT tunnel + TLS-in-TLS
│   └── rusthttp/         # Public API
└── profiles/             # Browser fingerprint configs (JSON)
```

## Chrome Target Values

```
SETTINGS frame (exact order):
  HEADER_TABLE_SIZE (0x1) = 65536
  ENABLE_PUSH (0x2) = 0
  INITIAL_WINDOW_SIZE (0x4) = 6291456
  MAX_HEADER_LIST_SIZE (0x6) = 262144

WINDOW_UPDATE (connection-level): 15663105

Pseudo-header order: :method, :authority, :scheme, :path
```

**唔好 send**：`MAX_CONCURRENT_STREAMS`、`MAX_FRAME_SIZE`（Chrome 唔 send）

## Key Dependencies

- `boring` (btls fork) — BoringSSL binding
- `tokio` — async runtime
- `bytes` — buffer management

**唔用**：`h2` crate、`hyper`、`reqwest`

## Phase 1 MVP Scope

1. TLS handshake with Chrome JA3/JA4 fingerprint
2. HTTP/2 SETTINGS/WINDOW_UPDATE parity
3. HPACK encoder (Chrome-style)
4. HTTP CONNECT proxy with auth
5. Single request/response cycle

**Phase 2 先做**：Cookie jar、redirect、connection pool、HTTP/1.1 fallback

## Testing Gate

Target: Apple Store HK（Akamai Bot Manager）
Pass criteria: `parts` value ≤ 4（ideally 3）

## References

- `PROPOSAL.md` — 完整 design doc + timeline + checkpoints
- Desktop `/Users/danli/Desktop/HTTP_CLIENT_REQUIREMENTS.md` — 原始 requirements
- Desktop `/Users/danli/Desktop/specters-fork.zip` — Dan 嘅 specters fork（有 proxy support 但 cert bug）
