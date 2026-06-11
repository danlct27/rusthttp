//! rusthttptool — Lightweight Rust HTTP client with Chrome TLS/HTTP2 fingerprint parity.
//!
//! # Example
//! ```no_run
//! use rusthttptool::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::builder()
//!         .chrome()
//!         .proxy("http://user:pass@host:port")
//!         .build()?;
//!
//!     let resp = client.get("https://example.com").send().await?;
//!     println!("{}", resp.status());
//!     Ok(())
//! }
//! ```

pub use rusthttptool_h2 as h2;
pub use rusthttptool_proxy as proxy;
pub use rusthttptool_tls as tls;

pub struct Client;
pub struct ClientBuilder;
pub struct Response;

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder
    }

    pub fn get(&self, _url: &str) -> RequestBuilder {
        RequestBuilder
    }
}

impl ClientBuilder {
    pub fn chrome(self) -> Self { self }
    pub fn proxy(self, _url: &str) -> Self { self }
    pub fn build(self) -> Result<Client, Box<dyn std::error::Error>> {
        Ok(Client)
    }
}

pub struct RequestBuilder;

impl RequestBuilder {
    pub async fn send(self) -> Result<Response, Box<dyn std::error::Error>> {
        todo!("implement")
    }
}

impl Response {
    pub fn status(&self) -> u16 { 200 }
}
