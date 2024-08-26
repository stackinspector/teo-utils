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

#[allow(deprecated)]
fn make_date(year: i32, month: u32, day: u32, offset: i32) -> chrono::Date<chrono::FixedOffset> {
    use chrono::TimeZone;
    let time_zone = chrono::FixedOffset::east_opt(offset * 3600).unwrap();
    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap();
    time_zone.from_local_date(&naive).unwrap()
}

fn main() {
    let secret_id = std::fs::read_to_string("sid").unwrap();
    let secret_key = std::fs::read_to_string("sk").unwrap();
    let zone_id = std::fs::read_to_string("zid").unwrap();
    let access = Access { secret_id, secret_key };

    use std::io::{Read, Write};

    // include
    let start_date = make_date(2024, 8, 24, 8);
    // exclude
    let end_date = make_date(2024, 8, 24, 8);
    let mut date = start_date;

    loop {
        let max_limit = 300;
        let payload = DownloadL7Logs {
            start_time: date.and_hms_opt(0, 0, 0).unwrap().to_rfc3339(),
            end_time: date.and_hms_opt(23, 59, 0).unwrap().to_rfc3339(),
            zone_ids: vec![zone_id.clone()],
            domains: None,
            limit: max_limit,
            offset: 0,
        };
        let req = build_request(&payload, now(), &access, None);
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
            assert!(gz_header.operating_system() == 3);
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

        let dst_filename = format!("{}-{zone_id}.xz", date.format("%Y%m%d"));
        let dst_file = std::fs::OpenOptions::new().create_new(true).write(true).open(dst_filename).unwrap();
        let mut xz_handle = xz2::write::XzEncoder::new(dst_file, 9);
        xz_handle.write_all(dst_buf.as_slice()).unwrap();

        date = date.checked_add_signed(chrono::TimeDelta::days(1)).unwrap();
        if date >= end_date {
            break;
        }
    }
}
