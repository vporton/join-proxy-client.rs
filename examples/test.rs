/// Test binary for the join-proxy-client library.
/// 
/// This binary demonstrates how to use the library functions.
use join_proxy_client;

fn main() {
    println!("Testing join-proxy-client library:");
    
    // Call the hello function
    join_proxy_client::hello();
    
    // Get and print the greeting
    let greeting = join_proxy_client::get_greeting();
    println!("Greeting: {}", greeting);
    
    println!("Test completed successfully!");
}
