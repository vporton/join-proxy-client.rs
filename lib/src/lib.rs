use base64::{Engine, engine::general_purpose::URL_SAFE};
use ic_cdk::{api::certified_data_set, call::Call};
use ic_cdk::management_canister::TransformArgs;
pub use ic_cdk::management_canister::{http_request, HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult, TransformContext};
use ic_certified_map::{leaf_hash, AsHashTree, Hash, HashTree::{self, Leaf}};
use serde::{Serialize, Deserialize};
use candid::CandidType;
use std::{borrow::Cow, collections::HashSet};
use std::collections::{HashMap, BTreeMap};
use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use url::Url;

/// HTTP headers as a map from header name to list of values
pub type HttpHeaders = HashMap<String, Vec<String>>;

/// HTTP request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub headers: HttpHeaders,
    pub url: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MyTime(u64);

impl Display for MyTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// TODO: Need Sha256?
impl AsHashTree for MyTime {
    fn root_hash(&self) -> Hash {
        leaf_hash(&Sha256::digest(self.0.to_le_bytes()))
    }

    fn as_hash_tree(&self) -> HashTree<'_> {
        Leaf(Cow::from(Sha256::digest(self.0.to_le_bytes()).to_vec()))
    }
}


/// HTTP requests checker for deduplication
#[derive(Debug, Clone)]
pub struct HttpRequestsChecker {
    /// Map from request hash to timestamp
    hashes: ic_certified_map::RbTree<Vec<u8>, MyTime>,
    /// Map from timestamp to set of request hashes
    times: BTreeMap<MyTime, HashSet<Vec<u8>>>,
}

impl HttpRequestsChecker {
    /// Create a new HTTP requests checker
    pub fn new() -> Self {
        let res = Self {
            hashes: ic_certified_map::RbTree::new(),
            times: BTreeMap::new(),
        };
        certified_data_set(&res.hashes.root_hash()); // TODO: Needed?
        res
    }

    /// Get current timestamp in nanoseconds
    fn now() -> MyTime {
        MyTime(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        )
    }

    /// Delete old HTTP requests based on timeout
    fn delete_old_http_requests(&mut self, timeout: u64) {
        let threshold = MyTime(Self::now().0 - timeout * 1_000_000_000); // Convert to nanoseconds
        
        while let Some((&min_time, hashes)) = self.times.first_key_value() {
            if min_time > threshold {
                break;
            }
            
            // Remove all hashes for this timestamp
            for hash in hashes {
                self.hashes.delete(hash);
            }
            
            // Remove the timestamp entry
            self.times.remove(&min_time);
        }
    }

    /// Announce an HTTP request hash (for deduplication)
    fn announce_http_request_hash(&mut self, hash: Vec<u8>, timeout: u64) {
        self.delete_old_http_requests(timeout);

        // If there's an old hash equal to this, first delete it to clean times
        if let Some(old_time) = self.hashes.get(&hash).copied() {
            self.hashes.delete(&hash);
            
            if let Some(subtree) = self.times.get_mut(&old_time) {
                subtree.remove(&hash);
                if subtree.is_empty() {
                    self.times.remove(&old_time);
                }
            }
        }

        let now = Self::now();

        // Insert into both maps
        self.hashes.insert(hash.clone(), now);
        self.times.entry(now).or_insert_with(HashSet::new).insert(hash);
        certified_data_set(&self.hashes.root_hash());
    }

    /// Announce an HTTP request (for deduplication)
    pub fn announce_http_request(&mut self, request: &HttpRequest, timeout: u64) {
        let hash = Self::hash_of_http_request(request);
        self.announce_http_request_hash(hash, timeout);
    }

    /// Check if an HTTP request hash exists
    pub fn check_http_request(&self, hash: &[u8]) -> bool {
        self.hashes.get(hash).is_some()
    }

    /// Convert HTTP method to string
    fn http_method_to_text(method: &HttpMethod) -> &'static str {
        match method {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::HEAD => "HEAD",
        }
    }

    /// Serialize HTTP request to bytes for hashing
    pub fn serialize_http_request(request: &HttpRequest) -> Vec<u8> {
        let method = Self::http_method_to_text(&request.method);
        
        // Convert headers to sorted list for consistent hashing
        let mut header_entries: Vec<_> = request.headers.iter().collect();
        header_entries.sort_by_key(|(k, _)| *k);
        
        let headers_list: Vec<String> = header_entries
            .into_iter()
            .map(|(name, values)| {
                format!("{}\t{}", name, values.join("\t"))
            })
            .collect();
        
        let headers_joined = headers_list.join("\r");
        
        // Extract path from URL (assuming HTTPS)
        let url_path = if request.url.starts_with("https://") {
            if let Ok(url) = Url::parse(&request.url) {
                url.path().to_string()
            } else {
                // Fallback: extract path manually
                let rest = &request.url[8..];
                let path_start = rest.find('/').unwrap_or(rest.len());
                rest[path_start..].to_string()
            }
        } else {
            request.url.clone()
        };

        let header_part = format!("{}\n{}\n{}", method, url_path, headers_joined);
        
        let mut result = header_part.into_bytes();
        result.push(b'\n');
        result.extend_from_slice(&request.body);
        result
    }

    /// Hash an HTTP request
    pub fn hash_of_http_request(request: &HttpRequest) -> Vec<u8> { // TODO: `[u8; 32]` return type.
        let blob = Self::serialize_http_request(request);
        let mut hasher = Sha256::new();
        hasher.update(&blob);
        hasher.finalize().to_vec()
    }

    /// Convert headers to lowercase
    fn headers_to_lowercase(headers: &mut HttpHeaders) {
        let mut to_update = Vec::new();
        
        for (key, values) in headers.iter() {
            let lower = key.to_lowercase();
            if lower != *key {
                to_update.push((key.clone(), lower, values.clone()));
            }
        }
        
        for (old_key, new_key, values) in to_update {
            headers.remove(&old_key);
            headers.insert(new_key, values);
        }
    }

    /// Modify HTTP request to add standard headers
    pub fn modify_http_request(request: &mut HttpRequest, config_id: String) {
        Self::headers_to_lowercase(&mut request.headers);

        // Add content-length if body is not empty
        if !request.body.is_empty() {
            request.headers.insert(
                "content-length".to_string(),
                vec![request.body.len().to_string()],
            );
        }

        // Add user-agent if missing
        if !request.headers.contains_key("user-agent") {
            request.headers.insert(
                "user-agent".to_string(),
                vec!["IC/for-Join-Proxy".to_string()],
            );
        }

        // Add accept header if missing
        if !request.headers.contains_key("accept") {
            request.headers.insert(
                "accept".to_string(),
                vec!["*/*".to_string()],
            );
        }

        // Add host header if missing
        if !request.headers.contains_key("host") {
            if let Ok(url) = Url::parse(&request.url) {
                if let Some(host) = url.host_str() {
                    let host_value = if let Some(port) = url.port() {
                        format!("{}:{}", host, port)
                    } else {
                        host.to_string()
                    };
                    request.headers.insert("host".to_string(), vec![host_value]);
                }
            }
        }

        request.headers.entry("x-config".to_string()).and_modify(|c| c.push(config_id.clone())).or_insert(vec![config_id]);
    }

    /// Make a checked HTTP request with deduplication
    pub async fn checked_http_request(
        &mut self,
        request: &mut HttpRequest,
        transform: Option<TransformContext>,
        params: HttpRequestParams,
        config_id: String,
    ) -> Result<HttpRequestResult, Box<dyn std::error::Error + Send + Sync>> {
        Self::modify_http_request(request, config_id);
        self.announce_http_request(request, params.timeout);

        let cert = ic_cdk::api::data_certificate().unwrap(); // FIXME: Must be called from a query call.
        let cert = URL_SAFE.encode(cert);
        // Remove the following header in the proxy before hashing.
        // TODO: `to_string` and `clone()` are inefficient.
        request.headers.entry("x-cert".to_string()).and_modify(|c| c.push(cert.clone())).or_insert(vec![cert]);

        // Execute request // TODO: Get rid of `clone()`?
        let response = http_request(&HttpRequestArgs  {
            url: request.url.clone(),
            method: request.method,
            headers: request
                .headers
                .clone()
                .into_iter()
                .map(|(name, values)| 
                    values.into_iter().map(move |value| ic_cdk::management_canister::HttpHeader { name: name.clone(), value })
                )
                .flatten()
                .collect(),
            body: request.body.clone().into(),
            transform: transform.clone(),
            max_response_bytes: params.max_response_bytes,
        }).await?;

        // Apply transform if provided
        // FIXME: Why us, not the management canister calls it? Seems wrong.
        if let Some(transform_fn) = transform {
            // FIXME: unbounded
            // TODO: `clone` here seems inefficient but inevitable. Any solution?
            Call::unbounded_wait(transform_fn.function.0.principal, &transform_fn.function.0.method)
                .with_arg(TransformArgs { response: response.clone(), context: transform_fn.context })
                .await?;
        }

        let headers: Vec<_> = response
            .headers
            .into_iter()
            .collect();
        
        Ok(HttpRequestResult {
            status: response.status,
            headers,
            body: response.body,
        })
    }
}

/// Parameters for HTTP requests
#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct HttpRequestParams {
    pub cycles: u64,
    pub timeout: u64,
    pub max_response_bytes: Option<u64>,
}

/// Shared wrapped HTTP request with array-based headers
#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct SharedWrappedHttpRequest {
    pub method: HttpMethod,
    pub headers: Vec<(String, Vec<String>)>,
    pub url: String,
    pub body: Vec<u8>,
}

impl HttpRequestsChecker {
    /// Make a checked HTTP request with wrapped request
    pub async fn checked_http_request_wrapped(
        &mut self,
        request: SharedWrappedHttpRequest,
        transform: Option<TransformContext>,
        params: HttpRequestParams,
        config_id: String,
    ) -> Result<HttpRequestResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut http_request = HttpRequest {
            method: request.method,
            headers: request.headers.into_iter().collect(),
            url: request.url,
            body: request.body,
        };

        self.checked_http_request(&mut http_request, transform, params, config_id).await
    }

    /// Create new headers map
    pub fn headers_new() -> HttpHeaders {
        HashMap::new()
    }
}

impl Default for HttpRequestsChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_to_text() {
        assert_eq!(HttpRequestsChecker::http_method_to_text(&HttpMethod::GET), "GET");
        assert_eq!(HttpRequestsChecker::http_method_to_text(&HttpMethod::POST), "POST");
        assert_eq!(HttpRequestsChecker::http_method_to_text(&HttpMethod::HEAD), "HEAD");
    }

    #[test]
    fn test_serialize_http_request() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);
        
        let request = HttpRequest {
            method: HttpMethod::POST,
            headers,
            url: "https://example.com/api".to_string(),
            body: b"{\"test\": \"data\"}".to_vec(),
        };

        let serialized = HttpRequestsChecker::serialize_http_request(&request);
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_hash_of_http_request() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);
        
        let request = HttpRequest {
            method: HttpMethod::POST,
            headers,
            url: "https://example.com/api".to_string(),
            body: b"{\"test\": \"data\"}".to_vec(),
        };

        let hash1 = HttpRequestsChecker::hash_of_http_request(&request);
        let hash2 = HttpRequestsChecker::hash_of_http_request(&request);
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_http_requests_checker() {
        let mut checker = HttpRequestsChecker::new();
        
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);
        
        let request = HttpRequest {
            method: HttpMethod::POST,
            headers,
            url: "https://example.com/api".to_string(),
            body: b"{\"test\": \"data\"}".to_vec(),
        };

        let hash = HttpRequestsChecker::hash_of_http_request(&request);
        
        // Initially should not exist
        assert!(!checker.check_http_request(&hash));
        
        // After announcing, should exist
        checker.announce_http_request_hash(hash.clone(), 3600);
        assert!(checker.check_http_request(&hash));
    }
}
