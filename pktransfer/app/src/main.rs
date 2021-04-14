// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..
#[macro_use]
extern crate rouille;
extern crate sgx_types;
extern crate sgx_urts;
// extern crate sgx_tseal;


#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_cbor;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::slice;

pub const SECRET_LEN: usize = 256;
pub const MAX_OUT_SIZE: usize = 4096;     // Maximum data can seal in bytes -> smaller than "HeapMaxSize" in Enclave.config.xml
pub const RETREIVE_SECRET_LEN: usize = 364;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern {
    fn init_db(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, n: * mut u8, e: * mut u8) -> sgx_status_t;
    fn signup(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
    fn host_retrieve(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, uid: u32) -> sgx_status_t;
    fn user_retrieve(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, uid: u32,
                        some_string: *const u8, len: usize, encrypted_secret: &mut [u8;RETREIVE_SECRET_LEN]) -> sgx_status_t;
    fn audit(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, db: * mut u8, max_len: usize, out_len: *mut usize) -> sgx_status_t;
    fn public_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, n: * mut u8, e: * mut u8) -> sgx_status_t;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditDatabase {
    timestamp: u64,
    retrieve_count: u64,
    users: Vec<Vec<u8>>,
    retrieve: Vec<Vec<u8>>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignupReq {
   secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostReq {
   uid: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserReq {
   uid: u32,
   secret: Vec<u8>,
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

fn init_db_enclave(eid: sgx_enclave_id_t, n: * mut u8, e: * mut u8) {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        init_db(eid, &mut retval, n, e)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    match retval {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", retval.as_str());
            return;
        }
    }
    println!("[+] init success...");
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let mut def_public_key_n: [u8; SECRET_LEN] = [0; SECRET_LEN];
    let mut public_key_n_ptr = def_public_key_n.as_ptr() as * mut u8;
    let mut def_public_key_e: [u8; 4] = [0; 4];
    let mut public_key_e_ptr = def_public_key_e.as_ptr() as * mut u8;
    init_db_enclave(enclave.geteid(), public_key_n_ptr, public_key_e_ptr);
    let public_key_n = unsafe { slice::from_raw_parts(public_key_n_ptr, SECRET_LEN) };
    println!("[+] public_key_n {:?}!", public_key_n);
    let public_key_e = unsafe { slice::from_raw_parts(public_key_e_ptr, 4) };
    println!("[+] public_key_e {:?}!", public_key_e);

    let eid = enclave.geteid();

    rouille::start_server("localhost:8000", move |request| {
        router!(request,
            (POST) (/signup) => {
                println!("signup request");
                // let signup_req: SignupReq = try_or_400!(rouille::input::json_input(&request));
                let signup_req: SignupReq = match rouille::input::json_input(&request) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("json_input err {} request {:#?}",e, request);
                        return rouille::Response::text(format!("Error parsing body json err {} request {:#?}", e, request)).with_status_code(400);
                    }
                };

                if signup_req.secret.len() != SECRET_LEN {
                    return rouille::Response::text(format!("Error parsing body secret len is {} not {}", signup_req.secret.len(), SECRET_LEN)).with_status_code(400);
                }

                let mut retval = sgx_status_t::SGX_SUCCESS;

                let result = unsafe {
                    signup(eid,
                          &mut retval,
                          signup_req.secret.as_ptr() as * const u8,
                          signup_req.secret.len())
                };

                match result {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave result Failed {}!", result.as_str())).with_status_code(400);
                    }
                }

                match retval {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave function Failed {}!", retval.as_str())).with_status_code(400);

                    }
                }

                println!("[+] signup success...");

                rouille::Response::text("success")
            },
            (POST) (/host) => {
                println!("host request");
                let host_req: HostReq = try_or_400!(rouille::input::json_input(&request));

                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result = unsafe {
                    host_retrieve(eid,
                                  &mut retval,
                                  host_req.uid)
                };
                match result {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave result Failed {}!", result.as_str())).with_status_code(400);
                    }
                }

                match retval {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave function Failed {}!", retval.as_str())).with_status_code(400);

                    }
                }
                println!("[+] host success...");

                rouille::Response::text("success")
            },
            (POST) (/user) => {
                println!("user request");
                let user_req: UserReq = try_or_400!(rouille::input::json_input(&request));
                // let user_req: UserReq = match rouille::input::json_input(&request) {
                //     Ok(x) => x,
                //     Err(e) => {
                //         println!("json_input err {} request {:#?}",e, request);
                //         return rouille::Response::text(format!("Error parsing body json err {} request {:#?}", e, request)).with_status_code(400);
                //     }
                // };

                if user_req.secret.len() != SECRET_LEN {
                    return rouille::Response::text(format!("Error parsing body secret len is {} not {}", user_req.secret.len(), SECRET_LEN)).with_status_code(400);
                }

                let mut retval = sgx_status_t::SGX_SUCCESS;
                let encrypted_secret: &mut [u8;RETREIVE_SECRET_LEN] = &mut [2; RETREIVE_SECRET_LEN];

                let result = unsafe {
                    user_retrieve(eid,
                                  &mut retval,
                                  user_req.uid,
                                  user_req.secret.as_ptr() as * const u8,
                                  user_req.secret.len(),
                                  encrypted_secret)
                };

                match result {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave result Failed {}!", result.as_str())).with_status_code(400);
                    }
                }

                match retval {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave function Failed {}!", retval.as_str())).with_status_code(400);

                    }
                }
                println!("[+] user success...");

                rouille::Response::text(std::str::from_utf8(&encrypted_secret.to_vec()).unwrap())
            },
            (GET)  (/public_key) => {
                #[derive(Serialize)]
                struct PK {
                    n: [[u8; 32]; 8],
                    e: [u8; 4],
                };
                let mut n_arr: [[u8; 32]; 8] = Default::default();
                n_arr[0].copy_from_slice(&public_key_n[0 .. 32]);
                n_arr[1].copy_from_slice(&public_key_n[32 .. 64]);
                n_arr[2].copy_from_slice(&public_key_n[64 .. 96]);
                n_arr[3].copy_from_slice(&public_key_n[96 .. 128]);
                n_arr[4].copy_from_slice(&public_key_n[128 .. 160]);
                n_arr[5].copy_from_slice(&public_key_n[160 .. 192]);
                n_arr[6].copy_from_slice(&public_key_n[192 .. 224]);
                n_arr[7].copy_from_slice(&public_key_n[224 .. 256]);
                println!("[+] public_key_n {:?}!", public_key_n);
                rouille::Response::json(&PK{n: n_arr, e: def_public_key_e})
            },
            (GET)  (/audit) => {
                println!("audit");
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let mut def: [u8; MAX_OUT_SIZE] = [4; MAX_OUT_SIZE];
                let mut ptr = def.as_ptr() as * mut u8;
                let mut size: usize = MAX_OUT_SIZE;
                let mut size_ptr: *mut usize = &mut size;
                let result = unsafe {
                    audit(eid,
                          &mut retval,
                          ptr,
                          MAX_OUT_SIZE,
                          size_ptr)
                };
                match result {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", result.as_str());
                        return rouille::Response::text(format!("ECALL Enclave result Failed {}!", result.as_str())).with_status_code(400);
                    }
                }

                match retval {
                    sgx_status_t::SGX_SUCCESS => {},
                    _ => {
                        println!("[-] ECALL Enclave Failed {}!", retval.as_str());
                        return rouille::Response::text(format!("ECALL Enclave function Failed {}!", retval.as_str())).with_status_code(400);
                    }
                }
                println!("[+] size {:?}!", size);
                let output = unsafe { slice::from_raw_parts(ptr, size) };
                println!("[+] output {:?}!", output);

                let db: AuditDatabase = match serde_cbor::from_slice(output) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("[-] deserialize err {}!", e);
                        return rouille::Response::text(format!("Deserialize err {}!", e)).with_status_code(400);
                    }
                };

                println!("[+] AuditDatabase {:?}!", db);
                let ret = match serde_json::to_string(&db){
                    Ok(x) => x,
                    Err(e) => {
                        println!("[-] serialize err {}!", e);
                        return rouille::Response::text(format!("Serialize err {}!", e)).with_status_code(400);
                    }
                };
                rouille::Response::text(ret)
            },
            // The code block is called if none of the other blocks matches the request.
            // We return an empty response with a 404 status code.
            _ => rouille::Response::empty_404()
        )
    });
    enclave.destroy();

}
