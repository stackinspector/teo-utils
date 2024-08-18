use std::io::{BufRead, Write};

fn main() {
    let mut args = std::env::args_os();
    let _ = args.next();
    let list_f_path = args.next().unwrap();
    let dst_f_path = args.next().unwrap();
    let list_f = std::fs::OpenOptions::new().read(true).open(list_f_path).unwrap();
    let list_fh = std::io::BufReader::new(list_f);
    let mut dst_h = std::fs::OpenOptions::new().create_new(true).write(true).open(dst_f_path).unwrap();
    let http = ureq::AgentBuilder::new().user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36").build();

    macro_rules! w {
        ($buf:expr) => {
            dst_h.write_all(&$buf).unwrap();
        };
    }

    macro_rules! ws {
        ($buf:expr) => {
            dst_h.write_all($buf.as_bytes()).unwrap();
        };
    }

    macro_rules! wn {
        ($num:expr) => {{
            let _n: u64 = $num.try_into().unwrap();
            dst_h.write_all(&_n.to_be_bytes()).unwrap();
        }};
    }

    // macro_rules! wl {
    //     () => {
    //         dst_h.write_all(b"\n").unwrap();
    //     };
    // }

    for line in list_fh.lines() {
        let line = line.unwrap();
        let line_l = line.len();
        let mut res_h = http.get(&line).call().unwrap().into_reader();
        let mut res_buf = Vec::new();
        let res_l = res_h.read_to_end(&mut res_buf).unwrap();
        assert_eq!(res_buf.len(), res_l);
        wn!(line_l);
        ws!(line);
        wn!(res_l);
        w!(res_buf);
    }
}