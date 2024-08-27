use tcapi_ureq_example::{
    tcapi_model::api::*,
    tcapi_client::Access,
    tcapi_req,
};

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

fn make_time_iso8601(
    date: chrono::NaiveDate,
    time_zone: &chrono::FixedOffset,
    hour: u32,
    min: u32,
    sec: u32,
) -> String {
    let naive = date.and_hms_opt(hour, min, sec).unwrap();
    let with_time_zone = chrono::TimeZone::from_local_datetime(time_zone, &naive).unwrap();
    with_time_zone.to_rfc3339()
}

fn parse_json<T: serde::de::DeserializeOwned>(p: std::ffi::OsString) -> T {
    let f = std::fs::File::open(p).unwrap();
    serde_json::from_reader(f).unwrap()
}

fn parse_date(p: std::ffi::OsString) -> chrono::NaiveDate {
    let s = p.into_string().unwrap();
    chrono::NaiveDate::parse_from_str(&s, "%Y%m%d").unwrap()
}

fn parse_time_zone(p: std::ffi::OsString) -> chrono::FixedOffset {
    let s = p.into_string().unwrap();
    let offset: i32 = s.parse().unwrap();
    chrono::FixedOffset::east_opt(offset * 3600).unwrap()
}

fn main() {
    let mut args = std::env::args_os();
    let _ = args.next();
    let access: Access = parse_json(args.next().unwrap());
    let zone_id = args.next().unwrap().into_string().unwrap();
    let start_date = parse_date(args.next().unwrap());
    let end_date = parse_date(args.next().unwrap());
    let time_zone = parse_time_zone(args.next().unwrap());

    use std::io::{Read, Write};

    let mut date = start_date;
    loop {
        let max_limit = 300;
        let payload = DownloadL7Logs {
            start_time: make_time_iso8601(date, &time_zone, 0, 0, 0),
            end_time: make_time_iso8601(date, &time_zone, 23, 59, 0),
            zone_ids: vec![zone_id.clone()],
            domains: None,
            limit: max_limit,
            offset: 0,
        };
        let res = tcapi_req(payload, &access);
        assert!(res.total_count <= max_limit); // empirical & adhoc

        let mut dst_buf = Vec::with_capacity(16777216); // empirical

        for item in res.data {
            let L7OfflineLog {
                domain,
                area,
                log_packet_name,
                url,
                log_time,
                log_start_time,
                log_end_time,
                size,
            } = item;
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

            println!("-> {gz_filename}");
            let url_without_query = remove_url_query(&url);
            let info = LogInfo {
                domain,
                area,
                log_packet_name,
                url_without_query,
                log_time,
                log_start_time,
                log_end_time,
                size,
                gz_filename,
                gz_mtime,
                uncompressed_size,
            };
            serde_json::to_writer(&mut dst_buf, &info).unwrap();
            dst_buf.extend_from_slice("\n".as_bytes());
            dst_buf.extend_from_slice(uncompressed_buf.as_bytes());
        }

        let dst_filename = format!("{}-{zone_id}.xz", date.format("%Y%m%d"));
        println!("<- {dst_filename}");
        let dst_file = std::fs::OpenOptions::new().create_new(true).write(true).open(dst_filename).unwrap();
        let mut xz_handle = xz2::write::XzEncoder::new(dst_file, 9);
        xz_handle.write_all(dst_buf.as_slice()).unwrap();

        date = date.checked_add_signed(chrono::TimeDelta::days(1)).unwrap();
        if date >= end_date {
            break;
        }
    }
}
