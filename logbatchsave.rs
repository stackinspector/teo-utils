#![deny(unused_results)]

use std::io::{Read, Write};

use tcapi_ureq_example::{
    tcapi_model::api::*,
    tcapi_client::Access,
    LocalUreqClient,
};

#[derive(serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct LogInfoBegin {
    domain: String,
    area: String,
    log_packet_name: String,
    url_without_query: String,
    log_time: u64,
    log_start_time: String, // ISO8601
    log_end_time: String, // ISO8601
    size: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "PascalCase")]
#[serde(tag = "type")]
enum LogInfoEnd {
    Ok {
        gz_filename: String,
        gz_mtime: u32,
        uncompressed_size: u64,
    },
    Err {
        status: Option<u16>,
    },
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

fn handle_a_segment(log_info: L7OfflineLog) -> Vec<u8> {
    let mut segment_buf = Vec::new();

    // begin
    let L7OfflineLog {
        domain,
        area,
        log_packet_name,
        url,
        log_time,
        log_start_time,
        log_end_time,
        size,
    } = log_info;
    let url_without_query = remove_url_query(&url);
    let info_begin = LogInfoBegin {
        domain,
        area,
        log_packet_name,
        url_without_query,
        log_time,
        log_start_time,
        log_end_time,
        size,
    };
    serde_json::to_writer(&mut segment_buf, &info_begin).unwrap();
    segment_buf.push(b'\n');

    let resp = ureq::get(&url).call();
    match resp {
        Ok(resp) => {
            let gz_handle = resp.into_reader();

            // content
            let mut gz_reader = flate2::read::MultiGzDecoder::new(gz_handle);
            let uncompressed_size = gz_reader.read_to_end(&mut segment_buf).unwrap() as u64;
            // let uncompressed_size = content.len().try_into().unwrap();
            // assert_eq!(uncompressed_size, uncompressed_size_);
        
            // end
            let gz_header = gz_reader.header().unwrap();
            assert!(gz_header.extra().is_none()); // .is_some_and(|v| v.is_empty())
            assert!(gz_header.comment().is_none());
            assert!(gz_header.operating_system() == 3);
            let gz_filename = String::from_utf8(gz_header.filename().unwrap().to_owned()).unwrap();
            println!("-> {gz_filename}");
            let gz_mtime = gz_header.mtime();
            let info_end = LogInfoEnd::Ok {
                gz_filename,
                gz_mtime,
                uncompressed_size,
            };
            serde_json::to_writer(&mut segment_buf, &info_end).unwrap();
            segment_buf.push(b'\n');
        
            // finish
            segment_buf
        }
        Err(err) => {
            println!("!! {url}");
            let status = match err {
                ureq::Error::Status(n, _) => Some(n),
                ureq::Error::Transport(_) => None,
            };
            let info_end = LogInfoEnd::Err {
                status,
            };
            serde_json::to_writer(&mut segment_buf, &info_end).unwrap();
            segment_buf.push(b'\n');
        
            segment_buf
        }
    }
}

struct Context {
    client: LocalUreqClient,
    time_zone: chrono::FixedOffset,
    max_limit: u32,
    zone_id: String,
}

impl Context {
    // fn handle_a_day(
    //     Context { client, time_zone, max_limit, zone_id }: &mut Self,
    //     date: chrono::NaiveDate,
    // ) {
    fn handle_a_day(&mut self, date: chrono::NaiveDate) {
        let Context { client, time_zone, max_limit, zone_id } = self;
        let payload = DownloadL7Logs {
            start_time: make_time_iso8601(date, &time_zone, 0, 0, 0),
            end_time: make_time_iso8601(date, &time_zone, 23, 59, 0),
            zone_ids: vec![zone_id.clone()],
            domains: None,
            limit: *max_limit,
            offset: 0,
        };
        let res = client.req(payload);
        assert!(res.total_count <= *max_limit); // empirical & adhoc
        let dst_filename = format!("{}-{}.xz", zone_id, date.format("%Y%m%d"));
        println!("<- {dst_filename}");
        let dst_file = std::fs::OpenOptions::new().create_new(true).write(true).open(dst_filename).unwrap();
        let mut xz_handle = xz2::write::XzEncoder::new(dst_file, 9);

        for item in res.data {
            xz_handle.write_all(&handle_a_segment(item)).unwrap();
        }
    }
}

fn derive_dates(start_date: chrono::NaiveDate, end_date: chrono::NaiveDate) -> Vec<chrono::NaiveDate> {
    let mut dates = Vec::new();
    let mut date = start_date;
    loop {
        dates.push(date);
        date = date.checked_add_signed(chrono::TimeDelta::days(1)).unwrap();
        if date >= end_date {
            break;
        }
    }
    dates
}

fn main() {
    let mut args = std::env::args_os();
    let _ = args.next();
    let access: Access = parse_json(args.next().unwrap());
    let zone_id = args.next().unwrap().into_string().unwrap();
    let start_date = parse_date(args.next().unwrap());
    let end_date = parse_date(args.next().unwrap());
    let time_zone = parse_time_zone(args.next().unwrap());
    let max_limit = 300;

    let mut context = Context {
        client: LocalUreqClient::new(access),
        time_zone,
        max_limit,
        zone_id,
    };
    let dates = derive_dates(start_date, end_date);
    for date in dates {
        context.handle_a_day(date);
    }
}
