#![allow(unused)]
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// TODO region

struct Access {
    secret_id: String,
    secret_key: String,
}

trait Service {
    const SERVICE: &'static str;
    const HOST: &'static str;
    const VERSION: &'static str;
}

enum Style {
    // Get,
    // PostForm,
    PostJson,
}

trait Action: Serialize {
    type Res: DeserializeOwned;
    type Service: Service;
    const STYLE: Style;
    const ACTION: &'static str;
}

struct EdgeOne;

impl Service for EdgeOne {
    const SERVICE: &'static str = "teo";
    const HOST: &'static str = "teo.tencentcloudapi.com";
    const VERSION: &'static str = "2022-09-01";
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DownloadL7Logs {
    start_time: String, // ISO8601
    end_time: String, // ISO8601
    zone_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domains: Option<Vec<String>>,
    limit: u32,
    offset: u32,
}

impl Action for DownloadL7Logs {
    type Res = DownloadL7LogsRes;
    type Service = EdgeOne;
    const STYLE: Style = Style::PostJson;
    const ACTION: &'static str = "DownloadL7Logs";
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct ResponseWrapper<T> {
    response: T,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct DownloadL7LogsRes {
    total_count: u32,
    data: Vec<L7OfflineLog>,
    request_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct L7OfflineLog {
    domain: String,
    area: String,
    log_packet_name: String,
    url: String,
    log_time: u64,
    log_start_time: String, // ISO8601
    log_end_time: String, // ISO8601
    size: u64,
}

fn timestamp_to_date(timestamp: u64) -> String {
    chrono::DateTime::from_timestamp(timestamp.try_into().unwrap(), 0).unwrap().format("%Y-%m-%d").to_string()
}

fn sha256<B: AsRef<[u8]>>(data: B) -> [u8; 32] {
    use sha2::Digest;
    let mut ctx = sha2::Sha256::new();
    ctx.update(data.as_ref());
    ctx.finalize().into()
}

fn hmac_sha256<B1: AsRef<[u8]>, B2: AsRef<[u8]>>(key: B1, data: B2) -> [u8; 32] {
    use hmac::Mac;
    let mut ctx = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_ref()).unwrap();
    ctx.update(data.as_ref());
    ctx.finalize().into_bytes().into()
}

macro_rules! header_value {
    (owned $v:expr) => {
        http::HeaderValue::from_str(&$v).unwrap()
    };
    (static $v:expr) => {
        http::HeaderValue::from_static($v)
    };
}
macro_rules! headers {
    (
        $request:expr;
        known {$($k1:ident => $t1:tt $v1:expr;)*}
        custom {$($k2:expr => $t2:tt $v2:expr;)*}
    ) => {{
        let headers = $request.headers_mut().unwrap();
        $(headers.append(http::header::$k1, header_value!($t1 $v1));)*
        $(headers.append($k2, header_value!($t2 $v2));)*
    }};
}

fn build_request<A: Action>(payload: &A, timestamp: u64, Access { secret_id, secret_key }: &Access) -> http::Request<String> {
    let service = A::Service::SERVICE;
    let host = A::Service::HOST;
    let version = A::Service::VERSION;
    let action = A::ACTION;
    let payload = serde_json::to_string(payload).unwrap();
    let algorithm = "TC3-HMAC-SHA256";
    let timestamp_string = timestamp.to_string(); /* TODO */
    let date = timestamp_to_date(timestamp);

    let http_request_method = match A::STYLE {
        Style::PostJson => "POST",
    };
    let canonical_uri = "/";
    let canonical_querystring = match A::STYLE {
        Style::PostJson => "",
        // get: payload -> urlencode
    };
    let content_type = match A::STYLE {
        Style::PostJson => "application/json; charset=utf-8",
    };
    let action_lowercase = action.to_ascii_lowercase(); // TODO const
    let canonical_headers = format!("content-type:{content_type}\nhost:{host}\nx-tc-action:{action_lowercase}\n");
    let signed_headers = "content-type;host;x-tc-action";
    let hashed_request_payload = hex::encode(sha256(&payload)); // TODO array string
    let canonical_request = [
        http_request_method,
        canonical_uri,
        canonical_querystring,
        canonical_headers.as_str(),
        signed_headers,
        hashed_request_payload.as_str(),
    ].join("\n");

    let credential_scope = format!("{date}/{service}/tc3_request");
    let hashed_canonical_request = hex::encode(sha256(canonical_request));
    let string_to_sign = [
        algorithm,
        timestamp_string.as_str(),
        credential_scope.as_str(),
        hashed_canonical_request.as_str(),
    ].join("\n");

    let secret_date = hmac_sha256(format!("TC3{secret_key}"), date);
    let secret_service = hmac_sha256(secret_date, service);
    let secret_signing = hmac_sha256(secret_service, "tc3_request");
    let signature = hex::encode(hmac_sha256(secret_signing, string_to_sign));

    let authorization = format!("{algorithm} Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}");

    let mut request = http::Request::builder().method(match A::STYLE {
        Style::PostJson => http::Method::POST,
    }).uri(canonical_uri);

    headers! {
        request;
        known {
            AUTHORIZATION => owned authorization;
            CONTENT_TYPE => static content_type;
            HOST => static host;
        } 
        custom {
            "X-TC-Action" => static action;
            "X-TC-Timestamp" => owned timestamp_string;
            "X-TC-Version" => static version;
        }
    }

    request.body(payload).unwrap()
}

fn now_raw() -> (bool, u64, u32) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let res = SystemTime::now().duration_since(UNIX_EPOCH);
    let dir = res.is_ok();
    let dur = res.unwrap_or_else(|err| err.duration());
    (dir, dur.as_secs(), dur.subsec_nanos())
}

fn now() -> u64 {
    let (dir, secs, nanos) = now_raw();
    assert!(dir);
    secs
}

fn ureq(req: http::Request<String>) -> Box<dyn std::io::Read + Send + Sync + 'static> {
    let (mut http_parts, body) = req.into_parts();
    let host = http_parts.headers.get(http::header::HOST).unwrap().to_str().unwrap();
    http_parts.uri = format!("https://{}/", host).parse().unwrap();
    let request: ureq::Request = http_parts.into();
    request.send_string(&body).unwrap().into_reader()
}

fn main() {
    let secret_id = std::fs::read_to_string("sid").unwrap();
    let secret_key = std::fs::read_to_string("sk").unwrap();
    let zone_id = std::fs::read_to_string("zid").unwrap();

    let payload = DownloadL7Logs {
        start_time: "2024-07-17T00:00:00+08:00".to_owned(),
        end_time: "2024-07-17T23:59:00+08:00".to_owned(),
        zone_ids: vec![zone_id],
        domains: None,
        limit: 300,
        offset: 0,
    };
    let access = Access { secret_id, secret_key };
    let req = dbg!(build_request(&payload, now(), &access));
    let res = ureq(req);
    let res: ResponseWrapper<DownloadL7LogsRes> = serde_json::from_reader(res).unwrap();
    dbg!(res);
}
