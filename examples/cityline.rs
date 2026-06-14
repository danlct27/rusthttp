//! Test rusthttp against Cityline — verify WAF bypass.

use rusthttp::Client;

#[tokio::main]
async fn main() {
    // Build Chrome-impersonating client
    let client = Client::builder()
        .chrome(None)
        .build()
        .expect("failed to build client");

    println!("=== Test 1: Cityline homepage ===");
    match client.get("https://www.cityline.com").send().await {
        Ok(resp) => {
            println!("Status: {}", resp.status());
            println!("Body length: {} bytes", resp.bytes().len());
            if let Some(server) = resp.header("server") {
                println!("Server: {}", server);
            }
            if resp.status() == 403 || resp.status() == 503 {
                println!("❌ BLOCKED by WAF");
            } else if resp.status() == 200 || resp.status() == 301 || resp.status() == 302 {
                println!("✅ PASSED WAF");
            }
        }
        Err(e) => println!("Error: {e}"),
    }

    println!("\n=== Test 2: Cityline mobile API endpoint ===");
    match client
        .get("https://www.cityline.com/utsvInternet/rest/mobile/init")
        .header("accept", "application/json")
        .send()
        .await
    {
        Ok(resp) => {
            println!("Status: {}", resp.status());
            println!("Body length: {} bytes", resp.bytes().len());
            if resp.status() == 403 || resp.status() == 503 {
                println!("❌ BLOCKED by WAF");
            } else {
                println!("✅ PASSED WAF");
                let text = resp.text();
                println!("Response preview: {}", &text[..text.len().min(200)]);
            }
        }
        Err(e) => println!("Error: {e}"),
    }

    println!("\n=== Test 3: Cityline .com.hk ===");
    match client.get("https://www.cityline.com.hk").send().await {
        Ok(resp) => {
            println!("Status: {}", resp.status());
            if resp.status() == 403 || resp.status() == 503 {
                println!("❌ BLOCKED by WAF");
            } else {
                println!("✅ PASSED WAF");
            }
        }
        Err(e) => println!("Error: {e}"),
    }
}
