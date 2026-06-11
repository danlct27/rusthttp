---
name: browser-profiles
inclusion: always
---

# Browser Fingerprint Profiles

## 設計目標

提供多個預設 browser profile，用戶可以一行 code 切換：

```rust
let client = Client::builder()
    .profile(Profile::Chrome136)  // 預設
    .build()?;

// 或者
let client = Client::builder()
    .profile(Profile::Firefox128)
    .build()?;
```

## 預設 Profiles（MVP 必須有）

| Profile | TLS | HTTP/2 | Priority |
|---------|-----|--------|----------|
| `Chrome136` | Chrome 136 ClientHello | Chrome SETTINGS | P0 (default) |
| `Chrome135` | Chrome 135 | Chrome SETTINGS | P1 |
| `Chrome134` | Chrome 134 | Chrome SETTINGS | P1 |
| `Edge136` | Edge 136 (same as Chrome) | Chrome SETTINGS | P2 |
| `Firefox128` | Firefox 128 ClientHello | Firefox SETTINGS | P2 |
| `Safari18` | Safari 18 ClientHello | Safari SETTINGS | P2 |

## Profile JSON Schema

每個 profile 係一個 JSON file，放喺 `profiles/` 目錄：

```json
{
  "_meta": {
    "browser": "Chrome",
    "version": "136.0.7103.113",
    "captured": "2026-06-10",
    "os": "macOS 15.5"
  },
  "tls": {
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ],
    "extensions_order": [
      "server_name",
      "extended_master_secret", 
      "renegotiation_info",
      "supported_groups",
      "ec_point_formats",
      "session_ticket",
      "application_layer_protocol_negotiation",
      "status_request",
      "signature_algorithms",
      "signed_certificate_timestamp",
      "key_share",
      "psk_key_exchange_modes",
      "supported_versions",
      "compress_certificate",
      "application_settings"
    ],
    "supported_groups": [
      "x25519",
      "secp256r1",
      "secp384r1"
    ],
    "signature_algorithms": [
      "ecdsa_secp256r1_sha256",
      "rsa_pss_rsae_sha256",
      "rsa_pkcs1_sha256"
    ],
    "grease": true,
    "alps": true
  },
  "h2": {
    "settings": [
      {"id": 1, "value": 65536},
      {"id": 2, "value": 0},
      {"id": 4, "value": 6291456},
      {"id": 6, "value": 262144}
    ],
    "window_update": 15663105,
    "priority": {
      "enabled": true,
      "weight": 256,
      "exclusive": true
    },
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"]
  }
}
```

## Profile 載入順序

1. 檢查 `profiles/` 目錄有冇 custom JSON
2. 冇就用 embedded default（compile 入 binary）
3. `Profile::Custom(path)` 支援 runtime 載入

## 新增 Profile 流程

1. 用 Chrome DevTools 或 `chrome://net-export/` capture 真實 handshake
2. 用 `scripts/capture-profile.py` parse 成 JSON
3. 放入 `profiles/chrome-XXX.json`
4. 加入 `Profile` enum

## Chrome vs Firefox vs Safari 主要分別

### TLS Extension Order
- **Chrome**: GREASE 喺最前，ALPS 喺尾
- **Firefox**: 冇 GREASE，冇 ALPS，extension 順序唔同
- **Safari**: 有 GREASE，冇 ALPS，順序又唔同

### HTTP/2 SETTINGS
| Setting | Chrome | Firefox | Safari |
|---------|--------|---------|--------|
| HEADER_TABLE_SIZE | 65536 | 65536 | 4096 |
| ENABLE_PUSH | 0 | 0 | 0 |
| MAX_CONCURRENT_STREAMS | (not sent) | 100 | 100 |
| INITIAL_WINDOW_SIZE | 6291456 | 131072 | 4194304 |
| MAX_FRAME_SIZE | (not sent) | 16384 | (not sent) |
| MAX_HEADER_LIST_SIZE | 262144 | 65536 | (not sent) |

### Pseudo-header Order
- **Chrome**: `:method, :authority, :scheme, :path`
- **Firefox**: `:method, :path, :authority, :scheme`
- **Safari**: `:method, :scheme, :path, :authority`

## 驗證

新 profile 必須通過：
1. JA3/JA4 hash match（對比真實 browser capture）
2. Akamai `parts` test（≤4）
3. TLS Fingerprint.io check
