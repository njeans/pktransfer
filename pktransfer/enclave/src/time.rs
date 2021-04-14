
use std::net::TcpStream;
use std::string::String;
use std::vec::Vec;

use http_req::{request::RequestBuilder, tls, uri::Uri};
// use std::ffi::CString;
use serde_json;
// use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime};

pub fn get_timestamp() -> u64 {
    match ipgeolocation() {
        Some(x) => {
            println!("ipgeolocation {}",x);
            return x;
        },
        None => {}
    };
    return 0;
}

fn ipgeolocation() -> Option<u64> {
    let hostname = "https://api.ipgeolocation.io/timezone?apiKey=157647b62b6d455fa06cc6c3830f2fd6";

    let addr: Uri = hostname.parse().unwrap();
    let host = match addr.host() {
        Some(x) => x,
        None => {
            println!("Err host");
            return None;
        }
    };
    let port = 443;

    let conn_addr = format!("{}:{}", host, port);

    let stream = TcpStream::connect(conn_addr).unwrap();

    let mut stream = tls::Config::default()
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap();

    let mut writer = Vec::new();

    let response = RequestBuilder::new(&addr)
        .header("Connection", "Close")
        .send(&mut stream, &mut writer)
        .unwrap();
    let res = String::from_utf8_lossy(&writer);

    let json_res: serde_json::Value = match serde_json::from_str(&res) {
        Ok(x) => x,
        Err(e) => {
           println!("Err json {:?}",e);
           return None;
       }
   };
    let unix = match json_res["date_time_unix"].as_f64(){
        Some(x) => {
            x as u64
        },
        None => {
            println!("Err get unix");
            return None;
        }
    };
    return Some(unix)
}
