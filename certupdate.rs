#![allow(unused)]

mod common;
use common::*;
mod tcapi;
use tcapi::*;
mod api;
use api::*;

#[derive(serde::Deserialize)]
struct Config {
    pub zone_id: String,
    pub hosts: Vec<String>,
    pub key_path: String,
    pub fullchain_path: String,
    pub alias_prefix: String,
}

fn timestamp_to_date(timestamp: i64) -> String {
    let datetime = chrono::DateTime::from_timestamp(timestamp, 0).unwrap();
    datetime.format("%Y%m%d").to_string()
}

fn parse_json<T: serde::de::DeserializeOwned>(p: std::ffi::OsString) -> T {
    let f = std::fs::File::open(p).unwrap();
    serde_json::from_reader(f).unwrap()
}

fn main() {
    let mut args = std::env::args_os();
    let _ = args.next();
    let access: Access = parse_json(args.next().unwrap());
    let config: Config = parse_json(args.next().unwrap());
    
    let cert_id = {
        let payload = UploadCertificate {
            certificate_public_key: std::fs::read_to_string(config.fullchain_path).unwrap(),
            certificate_private_key: std::fs::read_to_string(config.key_path).unwrap(),
            alias: format!("{}_{}", config.alias_prefix, timestamp_to_date(now())),
            allow_download: false,
            repeatable: false,
            certificate_type: CertificateType::SVR,
        };
        let UploadCertificateRes { certificate_id, repeat_cert_id } = tcapi_req(payload, &access);
        assert!(repeat_cert_id.len() == 0);
        certificate_id
    };

    {
        let payload = ModifyHostsCertificate {
            zone_id: config.zone_id,
            hosts: config.hosts,
            server_cert_info: vec![ServerCertInfo {
                cert_id,
            }],
            mode: HostsCertificateMode::sslcert,
        };
        let ModifyHostsCertificateRes { } = tcapi_req(payload, &access);
    }
}
