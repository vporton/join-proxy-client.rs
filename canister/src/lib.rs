#![feature(thread_local)]
use std::cell::RefCell;

use ic_cdk::{api::canister_self, management_canister::TransformFunc, query, update};
use join_proxy_client::{HttpRequestParams, HttpRequestsChecker, HttpResponsePayload, SharedWrappedHttpRequest, TransformContext};
use ic_cdk::management_canister::TransformArgs;
use static_init::{dynamic};

// TODO: Save/restore it on upgrade.
#[dynamic]
#[thread_local]
static REQUESTS_CHECKER: RefCell<HttpRequestsChecker> = RefCell::new(HttpRequestsChecker::new());

#[update]
async fn call_http(
    request: SharedWrappedHttpRequest,
    params: HttpRequestParams,
    config_id: String,
) -> HttpResponsePayload {
    let mut c: std::cell::RefMut<'_, HttpRequestsChecker> = REQUESTS_CHECKER.borrow_mut();
    c.checked_http_request_wrapped(
        request,
        Some(TransformContext {
            function: TransformFunc(candid::Func{principal: canister_self(), method: "transform".to_string()}),
            context: Vec::new(),
        }),
        params,
        config_id,
    ).await.unwrap() // TODO: `unwrap`
}

#[query]
fn transform(args: TransformArgs) -> HttpResponsePayload {
    // TODO: Date should instead be removed by the server config.
    let headers = args.response.headers.into_iter().filter(|h: &join_proxy_client::HttpHeader| h.name != "date").collect::<Vec<_>>();
    HttpResponsePayload {
        status: args.response.status,
        headers,
        body: args.response.body,
    }
}

ic_cdk::export_candid!();
