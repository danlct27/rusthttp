//! rusthttp CLI — Chrome-fingerprint HTTP client
//!
//! Usage:
//!   rusthttp <url> [--proxy <proxy_url>] [--profile <chrome|firefox|safari>]
//!
//! Examples:
//!   rusthttp https://example.com
//!   rusthttp https://api.target.com --proxy http://user:pass@host:8080
//!   rusthttp https://site.com --profile firefox

use std::env;
use std::process::ExitCode;

use rusthttp::Client;

fn print_usage() {
    eprintln!("rusthttp — Chrome-fingerprint HTTP client");
    eprintln!();
    eprintln!("Usage: rusthttp <url> [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --proxy <url>      HTTP CONNECT proxy (e.g., http://user:pass@host:8080)");
    eprintln!("  --profile <name>   TLS profile: chrome (default), firefox, safari");
    eprintln!("  --insecure         Skip TLS certificate verification");
    eprintln!("  -v, --verbose      Show response headers");
    eprintln!("  -h, --help         Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  rusthttp https://tls.peet.ws/api/all");
    eprintln!("  rusthttp https://httpbin.org/get --proxy http://proxy:8080");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_usage();
        return ExitCode::from(if args.len() < 2 { 1 } else { 0 });
    }

    let mut url: Option<String> = None;
    let mut proxy: Option<String> = None;
    let mut profile = "chrome";
    let mut insecure = false;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--proxy" => {
                i += 1;
                if i < args.len() {
                    proxy = Some(args[i].clone());
                }
            }
            "--profile" => {
                i += 1;
                if i < args.len() {
                    profile = match args[i].as_str() {
                        "chrome" | "firefox" | "safari" => args[i].as_str(),
                        _ => {
                            eprintln!("Unknown profile: {}. Using chrome.", args[i]);
                            "chrome"
                        }
                    };
                }
            }
            "--insecure" => insecure = true,
            "-v" | "--verbose" => verbose = true,
            arg if !arg.starts_with('-') && url.is_none() => {
                url = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let url = match url {
        Some(u) => u,
        None => {
            eprintln!("Error: URL required");
            print_usage();
            return ExitCode::from(1);
        }
    };

    // Build client
    let mut builder = Client::builder().chrome();  // Chrome fingerprint
    
    if profile != "chrome" {
        eprintln!("Note: only 'chrome' profile implemented, using chrome");
    }

    if let Some(ref p) = proxy {
        builder = builder.proxy(p);
    }

    if insecure {
        builder = builder.danger_accept_invalid_certs();
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {}", e);
            return ExitCode::from(1);
        }
    };

    // Send request
    match client.get(&url).send().await {
        Ok(resp) => {
            if verbose {
                eprintln!("HTTP {}", resp.status());
                for (k, v) in &resp.headers {
                    eprintln!("{}: {}", k, v);
                }
                eprintln!();
            }

            match resp.text() {
                Ok(text) => println!("{}", text),
                Err(_) => {
                    // Binary response — print byte count
                    println!("[binary response: {} bytes]", resp.body.len());
                }
            }

            if resp.status().as_u16() >= 400 {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Request failed: {}", e);
            ExitCode::from(1)
        }
    }
}
