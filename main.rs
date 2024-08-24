mod tcapi;
use tcapi::*;
mod api;
use api::*;

fn now_raw() -> (bool, u64, u32) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let res = SystemTime::now().duration_since(UNIX_EPOCH);
    let dir = res.is_ok();
    let dur = res.unwrap_or_else(|err| err.duration());
    (dir, dur.as_secs(), dur.subsec_nanos())
}

fn now() -> u64 {
    let (dir, secs, _nanos) = now_raw();
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

#[derive(serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct LogInfo {
    domain: String,
    area: String,
    log_packet_name: String,
    url_without_query: String,
    log_time: u64,
    log_start_time: String, // ISO8601
    log_end_time: String, // ISO8601
    size: u64,
    gz_filename: String,
    gz_mtime: u32,
    uncompressed_size: u64,
}

fn remove_url_query(url: &str) -> String {
    let mut url = url.parse::<url::Url>().unwrap();
    url.set_query(None);
    url.into()
}

fn main() {
    let secret_id = std::fs::read_to_string("sid").unwrap();
    let secret_key = std::fs::read_to_string("sk").unwrap();
    let zone_id = std::fs::read_to_string("zid").unwrap();

    use std::io::{Read, Write};

    let max_limit = 300;
    let payload = DownloadL7Logs {
        start_time: "2024-07-17T00:00:00+08:00".to_owned(),
        end_time: "2024-07-17T23:59:00+08:00".to_owned(),
        zone_ids: vec![zone_id],
        domains: None,
        limit: max_limit,
        offset: 0,
    };
    let access = Access { secret_id, secret_key };
    let req = build_request(&payload, now(), &access);
    println!("{:?}", req);
    let res = ureq(req);
    let res: ResponseWrapper<DownloadL7LogsRes> = serde_json::from_reader(res).unwrap();
    let res = res.response;
    assert!(res.total_count <= max_limit); // empirical & adhoc

    let mut dst_buf = Vec::with_capacity(16777216); // empirical

    for item in res.data {
        let L7OfflineLog { domain, area, log_packet_name, url, log_time, log_start_time, log_end_time, size } = item;
        let gz_handle = ureq::get(&url).call().unwrap().into_reader();

        let mut gz_reader = flate2::read::MultiGzDecoder::new(gz_handle);
        let mut uncompressed_buf = String::new();
        gz_reader.read_to_string(&mut uncompressed_buf).unwrap();
        let uncompressed_size = uncompressed_buf.len().try_into().unwrap();

        let gz_header = gz_reader.header().unwrap();
        assert!(gz_header.extra().is_none()); // .is_some_and(|v| v.is_empty())
        assert!(gz_header.comment().is_none());
        let gz_filename = String::from_utf8(gz_header.filename().unwrap().to_owned()).unwrap();
        let gz_mtime = gz_header.mtime();

        let url_without_query = remove_url_query(&url);
        let info = LogInfo { domain, area, log_packet_name, url_without_query, log_time, log_start_time, log_end_time, size, gz_filename, gz_mtime, uncompressed_size };
        let info = serde_json::to_string(&info).unwrap();
        println!("{}", info);
        dst_buf.extend_from_slice(info.as_bytes());
        dst_buf.extend_from_slice("\n".as_bytes());
        dst_buf.extend_from_slice(uncompressed_buf.as_bytes());
    }

    let dst_file = std::fs::OpenOptions::new().create_new(true).write(true).open("dst").unwrap();
    let mut xz_handle = xz2::write::XzEncoder::new(dst_file, 9);
    xz_handle.write_all(dst_buf.as_slice()).unwrap();
}
