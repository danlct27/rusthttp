---
name: coding-standards
inclusion: always
---

# rusthttp Coding Standards

> 所有 contributor（包括 AI agent）寫 code 必須跟。

## Rust Style

- **Edition**: 2024
- **MSRV**: latest stable
- `cargo fmt` before commit（`rustfmt.toml` 跟 workspace default）
- `cargo clippy -- -D warnings` must pass
- No `unwrap()` in library code — use `?` or explicit error handling
- No `unsafe` unless absolutely necessary（TLS FFI 除外）— 每個 `unsafe` block 必須有 `// SAFETY:` comment

## Naming

- Crates: `rusthttp-{name}` (e.g. `rusthttp-tls`, `rusthttp-h2`)
- Modules: snake_case
- Types: PascalCase
- Functions: snake_case
- Constants: SCREAMING_SNAKE_CASE
- Error types: `{Module}Error` (e.g. `TlsError`, `H2Error`, `ProxyError`)

## Error Handling

- Per-crate error enum with `#[derive(Debug, thiserror::Error)]`
- `client` crate wraps all sub-errors with `#[from]`
- No `anyhow` in library code（examples/tests 可以用）
- Error messages: lowercase, no trailing period, include relevant context

```rust
#[derive(Debug, thiserror::Error)]
pub enum H2Error {
    #[error("settings frame exceeds max size: {size}")]
    SettingsTooLarge { size: usize },
    #[error("stream {id} in invalid state for {operation}")]
    InvalidStreamState { id: u32, operation: &'static str },
}
```

## Dependencies

- Minimal — 每加一個 dependency 要有 clear justification
- Pin exact versions in workspace `Cargo.toml`
- 唔用: `hyper`, `h2`, `reqwest`, `rustls`, `dashmap`, `anyhow`
- 只用: `boring`, `tokio`, `bytes`, `http`, `thiserror`, `tracing`, `serde`, `serde_json`, `base64`, `url`

## Module Structure

- 每個 file < 500 行（超過就 split）
- Public API 只 expose 喺 `lib.rs`，internal modules 用 `pub(crate)`
- 每個 public function/struct 要有 doc comment (`///`)
- 每個 module 頂部要有 `//!` module-level doc

## Testing

- Unit tests 放喺同一個 file 底部 `#[cfg(test)] mod tests {}`
- Integration tests 放 `tests/` directory
- 命名: `test_{function}_{scenario}_{expected}`
- Fingerprint regression tests: golden file byte comparison
- **Gate rule**: fingerprint assertion fail = 唔准 merge

## Performance

- Avoid unnecessary allocations — prefer `&[u8]` over `Vec<u8>` where lifetime allows
- Use `bytes::Bytes` / `BytesMut` for network buffers
- No blocking calls in async code — use `tokio::task::spawn_blocking` if needed
- Connection reuse > new connection（Phase 2 pool）

## Git

- Commit messages: `feat:` / `fix:` / `refactor:` / `docs:` / `test:` prefix
- One logical change per commit
- PR < 500 lines diff
- Branch naming: `feat/{description}` or `fix/{description}`

## Chrome Parity Rules（最重要）

- **SETTINGS frame**: exactly 4 params, exact order (`1, 2, 4, 6`), exact values
- **WINDOW_UPDATE**: sent immediately after SETTINGS, stream 0, value 15663105
- **Pseudo-header order**: `:method, :authority, :scheme, :path` — NEVER change
- **HPACK**: match Chrome's encoding decisions (static table preference, literal-without-indexing for most headers)
- Any change to frame/header ordering MUST be verified against golden pcap before merge
- 唔好 "improve" Chrome's behavior — even if spec says optional, if Chrome does it, we do it

## Security

- No secrets in code（use env vars）
- `danger_accept_invalid_certs` must be opt-in, default false
- Proxy credentials: never log, never include in error messages
- TLS: always verify hostname by default（proxy tunnel 時 verify target, not proxy）
