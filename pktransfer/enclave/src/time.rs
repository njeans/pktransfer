use std::net::TcpStream;
use std::string::String;
use std::vec::Vec;

use http_req::{request::RequestBuilder, tls, uri::Uri};
use serde_json;

pub fn get_timestamp() -> u64 {
    println!("get_timestamp");
    match timezonedb() {
        Some(x) => {
            println!("timezonedb {}",x);
            return x;
        },
        None => {}
    };
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

    let addr: Uri = match hostname.parse() {
        Ok(x) => x,
        Err(e) => {
            println!("Err hostname parse {:?}",e);
            return None;
        }
    };
    let host = match addr.host() {
        Some(x) => x,
        None => {
            println!("Err host");
            return None;
        }
    };
    let port = 443;

    let conn_addr = format!("{}:{}", host, port);

    let stream = match TcpStream::connect(conn_addr) {
        Ok(x) => x,
        Err(e) => {
            println!("Err TcpStream::connect {:?}",e);
            return None;
        }
    };

    let mut stream = match tls::Config::default().connect(addr.host().unwrap_or(""), stream) {
            Ok(x) => x,
            Err(e) => {
                println!("Err tls::connect {:?}",e);
                return None;
            }
    };

    let mut writer = Vec::new();

    let response = match RequestBuilder::new(&addr)
        .header("Connection", "Close")
        .send(&mut stream, &mut writer) {
            Ok(x) => x,
            Err(e) => {
                println!("Err get response {:?}",e);
                return None;
            }
    };
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

fn timezonedb() -> Option<u64> {
    let hostname = "http://api.timezonedb.com/v2.1/get-time-zone?key=G6905DVGFEKH&format=json&by=zone&zone=America/Chicago";
    let addr: Uri = match hostname.parse(){
        Ok(x) => x,
        Err(e) => {
            println!("Err hostname parse {:?}",e);
            return None;
        }
    };
    let host = match addr.host() {
        Some(x) => x,
        None => {
            println!("Err host");
            return None;
        }
    };

    let port = 443;

    let conn_addr = format!("{}:{}", host, port);

    let stream = match TcpStream::connect(conn_addr) {
        Ok(x) => x,
        Err(e) => {
            println!("Err TcpStream::connect {:?}",e);
            return None;
        }
    };

    let mut stream = match tls::Config::default().connect(addr.host().unwrap_or(""), stream) {
        Ok(x) => x,
        Err(e) => {
            println!("Err tls::connect {:?}",e);
            return None;
        }
    };

    let mut writer = Vec::new();

    let response = match RequestBuilder::new(&addr)
        .header("Connection", "Close")
        .send(&mut stream, &mut writer) {
            Ok(x) => x,
            Err(e) => {
                println!("Err get response {:?}",e);
                return None;
            }
    };
    let res = String::from_utf8_lossy(&writer);

    let json_res: serde_json::Value = match serde_json::from_str(&res) {
        Ok(x) => x,
        Err(e) => {
           println!("Err json {:?}",e);
           return None;
       }
    };
    if json_res["status"] == "OK" {
        println!("{:?}",json_res);
        return json_res["timestamp"].as_u64();
    }
    return None;
}
