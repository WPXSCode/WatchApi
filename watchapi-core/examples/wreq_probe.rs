use std::time::Duration;

use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use wreq::{Client as WreqClient, Proxy as WreqProxy};
use wreq_util::Emulation;

const DEFAULT_URL: &str = "https://api.hanhegufei.online/v1/responses";
const DEFAULT_PROXY: &str = "http://127.0.0.1:7897";

fn main() -> Result<()> {
    let url = std::env::var("WATCHAPI_PROBE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let proxy = std::env::var("WATCHAPI_PROBE_PROXY").unwrap_or_else(|_| DEFAULT_PROXY.to_string());
    let body = r#"{"model":"gpt-5.4","input":"ping"}"#;

    println!("url={url}");
    println!("proxy={proxy}");
    probe_wreq("wreq direct", &url, None, body)?;
    probe_wreq("wreq proxy", &url, Some(&proxy), body)?;
    probe_reqwest("reqwest proxy", &url, Some(&proxy), body)?;
    Ok(())
}

fn common_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer sk-dummy"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers
}

fn probe_wreq(label: &str, url: &str, proxy: Option<&str>, body: &str) -> Result<()> {
    let mut builder = WreqClient::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(40))
        .emulation(Emulation::Chrome132);
    if let Some(proxy) = proxy {
        builder = builder.proxy(WreqProxy::all(proxy)?);
    }
    let client = builder.build()?;
    let runtime = tokio::runtime::Runtime::new()?;
    println!("--- {label} ---");
    match runtime.block_on(async {
        client
            .post(url)
            .headers(common_headers())
            .body(body.as_bytes().to_vec())
            .send()
            .await
    }) {
        Ok(response) => {
            let status = response.status();
            let payload = runtime.block_on(async { response.text().await })?;
            println!("status={status}");
            println!("body={payload}");
        }
        Err(err) => {
            println!("error={err:?}");
            let mut source = std::error::Error::source(&err);
            while let Some(err) = source {
                println!("caused_by={err:?}");
                source = err.source();
            }
        }
    }
    Ok(())
}

fn probe_reqwest(label: &str, url: &str, proxy: Option<&str>, body: &str) -> Result<()> {
    let mut builder = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(40));
    if let Some(proxy) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    let client = builder.build()?;
    println!("--- {label} ---");
    match client
        .post(url)
        .headers(common_headers())
        .body(body.as_bytes().to_vec())
        .send()
    {
        Ok(response) => {
            let status = response.status();
            let payload = response.text()?;
            println!("status={status}");
            println!("body={payload}");
        }
        Err(err) => {
            println!("error={err:?}");
            let mut source = std::error::Error::source(&err);
            while let Some(err) = source {
                println!("caused_by={err:?}");
                source = err.source();
            }
        }
    }
    Ok(())
}
