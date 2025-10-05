/// Test binary for the join-proxy-client library.
/// 
/// This binary demonstrates how to use the library functions.
use join_proxy_client::{HttpRequestsChecker, HttpRequest, HttpMethod};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing join-proxy-client library:");
    
    // Create a new HTTP requests checker
    let mut checker = HttpRequestsChecker::new();
    
    // Create a test HTTP request
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);
    
    let mut request = HttpRequest {
        method: HttpMethod::POST,
        headers,
        url: "https://httpbin.org/post".to_string(),
        body: b"{\"test\": \"data\"}".to_vec(),
    };
    
    // Test serialization
    let serialized = HttpRequestsChecker::serialize_http_request(&request);
    println!("Serialized request length: {} bytes", serialized.len());
    
    // Test hashing
    let hash = HttpRequestsChecker::hash_of_http_request(&request);
    println!("Request hash: {:?}", hash);
    
    // Test deduplication
    println!("Request exists before announcing: {}", checker.check_http_request(&hash));
    checker.announce_http_request(&request, 3600);
    println!("Request exists after announcing: {}", checker.check_http_request(&hash));
    
    // Test HTTP request modification
    HttpRequestsChecker::modify_http_request(&mut request, "xxx".to_string());
    println!("Modified request headers: {:?}", request.headers);
    
    // Test making an actual HTTP request (commented out to avoid network dependency in tests)
    /*
    let params = HttpRequestParams {
        cycles: 1000000,
        timeout: 3600,
        max_response_bytes: Some(1024 * 1024), // 1MB
    };
    
    match checker.checked_http_request(&mut request, None, params).await {
        Ok(response) => {
            println!("HTTP request successful!");
            println!("Status: {}", response.status);
            println!("Response body length: {} bytes", response.body.len());
        }
        Err(e) => {
            println!("HTTP request failed: {}", e);
        }
    }
    */
    
    println!("Test completed successfully!");
    Ok(())
}
