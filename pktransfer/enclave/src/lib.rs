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

#![crate_name = "pktransferenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// #[cfg(target_env = "sgx")]
extern crate sgx_types;
extern crate sgx_tseal;
extern crate sgx_tcrypto;
extern crate sgx_trts;

#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate serde_json;
// extern crate chrono;
extern crate http_req;
extern crate ring;
extern crate base64;

mod time;
mod crypto;
// use time;

use std::string::String;
use std::vec::Vec;
use std::collections::HashMap;
use std::untrusted::fs::File;
use std::io::{self, Read, Write};
use std::slice;

use sgx_types::*;
use sgx_tcrypto::*;
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use ring::{aead, error};


pub const DATAFILE: &str = "data.sealed";
pub const SEAL_LOG_SIZE: usize = 4096*2;     // Maximum data can seal in bytes -> smaller than "HeapMaxSize" in Enclave.config.xml
pub const SYMMETRIC_KEY_LEN: usize = 32 + aead::NONCE_LEN;
pub const UID_SIZE: usize = 4;
pub const MAX_RETREIVE: u64 = 5;
pub const RESET_SECONDS: u64 = 86400; //24 hours
// pub const RESET_SECONDS: u64 = 60;

pub enum Error {
    SliceError,
    UnsealError(sgx_status_t),
    SerializeError,
    Other
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
   count: u64,
   secret: crypto::SecretData,
   encrypted_secret: crypto::SecretData,
   uid: u32,
   last_retreive: u64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Database {
    count: u64,
    data: HashMap<u32, Entry>,
    retrieve_queue: Vec<u32>,
    completed_queue: Vec<u32>,
    rsa_key: crypto::RSAKeyPair,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AuditDatabase {
    timestamp: u64,
    retrieve_count: u64,
    users: Vec<Vec<u8>>,
    retrieve: Vec<Vec<u8>>
}

#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a in-Enclave ";
    // An array
    let word:[u8;4] = [82, 117, 115, 116];
    // An vector
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
                                               .as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn init_db(out_encoded_public_key_n: &mut [u8; crypto::SECRET_DATA_LEN], out_encoded_public_key_e: &mut [u8; 4]) -> sgx_status_t {
    println!("Init db");
    match File::open(DATAFILE) {
        Ok(_) => {
            println!("DATAFILE exists");
            return public_key(out_encoded_public_key_n, out_encoded_public_key_e);
        },
        Err(e) => {
            println!("Error {} creating new db file",e);
        }
    }

    let mut rsa_key: crypto::RSAKeyPair = crypto::RSAKeyPair::new();

    let mut pubkey = crypto::RSAPublicKey::new();

    match crypto::build_rsa_key(&mut rsa_key, &mut pubkey) {
        sgx_status_t::SGX_SUCCESS => {

        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }

    println!("pubkey.get_n() {:?}", pubkey.get_n());
    println!("pubkey.get_e() {:?}", pubkey.get_e());

    *out_encoded_public_key_n = pubkey.get_n();
    *out_encoded_public_key_e = pubkey.get_e();

    let database = build_database(rsa_key);
    let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
    let p = DATAFILE;

    match create_sealeddata_for_db(database, &mut sealed_log_in) {
        sgx_status_t::SGX_SUCCESS => {
            return save_sealed_data(&p, &sealed_log_in);
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}

#[no_mangle]
pub extern "C" fn signup(encrypted_secret_ptr: *const u8, secret_size: usize) -> sgx_status_t {
    println!("sign up");
    if secret_size != crypto::SECRET_DATA_LEN {
        println!("secret_size {} must be {}", secret_size, crypto::SECRET_DATA_LEN);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let encrypted_secret_slice = unsafe { slice::from_raw_parts(encrypted_secret_ptr, secret_size) };
    println!("encrypted_secret_slice {:?}", encrypted_secret_slice);

    let mut database = match unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    println!("database {:?}", database);


    let mut encrypted_secret: [u8; crypto::SECRET_DATA_LEN]= [1; crypto::SECRET_DATA_LEN];
    encrypted_secret.copy_from_slice(encrypted_secret_slice);
    println!("encrypted_secret {:?}", encrypted_secret);

    let privkey = SgxRsaPrivKey::new();
    match database.rsa_key.private_key(&privkey) {
        sgx_status_t::SGX_SUCCESS => {

        }
        e => {
            println!("Error recover private_key");
            return e;
        }
    }

    let mut decrypted_secret = [0_u8; crypto::SECRET_DATA_LEN];
    let mut decrypted_secret_len: usize = decrypted_secret.len();
    match crypto::decrypt_rsa(&mut decrypted_secret, &mut decrypted_secret_len, &encrypted_secret, privkey) {
        sgx_status_t::SGX_SUCCESS => {

        }
        e => {
            println!("Error decrypt encrypted_retreival_key {:}",e);
            return e;
        }
    };

    let (uid_entry, _) = decrypted_secret.split_at(UID_SIZE);
    println!("uid_entry {:?}",uid_entry);
    let mut uid_arr: [u8; UID_SIZE] = Default::default();
    uid_arr.copy_from_slice(uid_entry);
    let uid = u32::from_be_bytes(uid_arr);
    println!("uid {:?}",uid);
    let _ = io::stdout().write(&decrypted_secret);
    println!("\n");
    if database.data.contains_key(&uid) {
        println!("Error uid already found");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    } else {
        let entry = build_entry(uid, &decrypted_secret, decrypted_secret_len, &encrypted_secret);
        database.data.insert(uid, entry);
        let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
        let p = DATAFILE;
        println!("final database {:?}", database);
        match create_sealeddata_for_db(database, &mut sealed_log_in) {
            sgx_status_t::SGX_SUCCESS => {
                println!("save_sealed_data(&p, &sealed_log_in);");
                return save_sealed_data(&p, &sealed_log_in);
            }
            _ => {
                println!("return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;");
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn host_retrieve(uid: u32) -> sgx_status_t {
    println!("host_retrieve enclave");

    let mut database: Database = match unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    if !database.data.contains_key(&uid) {
        println!("Error uid not found");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    if database.retrieve_queue.contains(&uid) {
      return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    } else {
        database.retrieve_queue.push(uid);
        let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
        let p = DATAFILE;
        println!("final database {:?}", database);
        match create_sealeddata_for_db(database, &mut sealed_log_in) {
            sgx_status_t::SGX_SUCCESS => {
                return save_sealed_data(&p, &sealed_log_in);
            }
            _ => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    }

}

#[no_mangle]
pub extern "C" fn user_retrieve(uid: u32, encrypted_retreival_key_ptr: *const u8, encrypted_retreival_key_size: usize, out_encrypted_user_data: &mut [u8; crypto::RETREIVE_SECRET_LEN]) -> sgx_status_t {
    println!("user_retrieve enclave");
    if encrypted_retreival_key_size != crypto::SECRET_DATA_LEN {
        println!("encrypted_retreival_key_size {} must be {}", encrypted_retreival_key_size, crypto::SECRET_DATA_LEN);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let mut database: Database = match unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    let mut entry: &mut Entry  = match database.data.get_mut(&uid) {
        Some(x) => x,
        None => {
            println!("Error cannot find uid {:?} {:?}", uid, database.data.contains_key(&uid));
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };
    if entry.count > 0 {
        println!("Error entry count {}", entry.count);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    if !database.retrieve_queue.contains(&uid) {
        println!("Error cannot find uid in retrieve_queue");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    } else {
        println!("encrypted_retreival_key_size {:?}", encrypted_retreival_key_size);

        let encrypted_retreival_key_slice = unsafe { slice::from_raw_parts(encrypted_retreival_key_ptr, crypto::SECRET_DATA_LEN) };
        println!("encrypted_retreival_key_slice {:?}", encrypted_retreival_key_slice);

        let mut encrypted_retreival_key: [u8; crypto::SECRET_DATA_LEN]= [1; crypto::SECRET_DATA_LEN];
        encrypted_retreival_key.copy_from_slice(encrypted_retreival_key_slice);
        println!("secret {:?}", encrypted_retreival_key);
        let privkey = SgxRsaPrivKey::new();
        match database.rsa_key.private_key(&privkey) {
            sgx_status_t::SGX_SUCCESS => {

            }
            e => {
                println!("Error recover private_key");
                return e;
            }
        }
        let mut encoded_decrypted_retreival_key = [0_u8; crypto::SECRET_DATA_LEN];
        let mut encoded_decrypted_retreival_key_len: usize = encoded_decrypted_retreival_key.len();
        match crypto::decrypt_rsa(&mut encoded_decrypted_retreival_key, &mut encoded_decrypted_retreival_key_len, &encrypted_retreival_key, privkey) {
        // match crypto::decrypt_rsa(&mut encoded_decrypted_retreival_key, &encrypted_retreival_key, privkey) {
            sgx_status_t::SGX_SUCCESS => {

            }
            e => {
                println!("Error decrypt encrypted_retreival_key {:}",e);
                return e;
            }
        };
        println!("encoded_decrypted_retreival_key {:?}",encoded_decrypted_retreival_key);
        let aead_seal_key = match base64::decode(&encoded_decrypted_retreival_key[0..44]) {
            Ok(x) => x,
            Err(e) => {
                println!("Err aead_seal_key {:?}",e);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        };
        let aead_nonce = match base64::decode(&encoded_decrypted_retreival_key[44..60]) {
            Ok(x) => x,
            Err(e) => {
                println!("Err aead_nonce {:?}",e);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        };
        // println!("decrypted_retreival_key {:?}",decrypted_retreival_key);
        // let (aead_seal_key, aead_nonce_extra) = decrypted_retreival_key.split_at(32);
        // let (aead_nonce, o) = aead_nonce_extra.split_at(aead::NONCE_LEN);
        println!("aead_seal_key {:?} \naead_nonce {:?}", aead_seal_key, aead_nonce);

        let mut aead_seal_key_arr: [u8; 32] = Default::default();
        aead_seal_key_arr.copy_from_slice(&aead_seal_key);
        let mut aead_nonce_arr: [u8; aead::NONCE_LEN] = Default::default();
        aead_nonce_arr.copy_from_slice(&aead_nonce);

        let mut aead_key = match crypto::build_aead_key(aead_seal_key_arr, aead_nonce_arr) {
            Ok(x) => x,
            Err(_e) => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        };
        let mut ciphertext =  vec![0; crypto::SECRET_DATA_LEN];

        match crypto::encrypt_aead(&mut ciphertext, &entry.secret.data(), &mut aead_key) {
            Ok(_) => {
                let encoded_ciphertext = base64::encode(ciphertext);
                if encoded_ciphertext.len() != crypto::RETREIVE_SECRET_LEN {
                    println!("Error encoded_ciphertext len {:?} {:?}", encoded_ciphertext.len(), encoded_ciphertext);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                out_encrypted_user_data.copy_from_slice(&encoded_ciphertext.as_bytes()[0..crypto::RETREIVE_SECRET_LEN])
            },
            Err(_e) => {
                println!("Error encrypt");
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        };


        println!("out_encrypted_user_data {:?}", out_encrypted_user_data);

        entry.count = entry.count + 1;
        let index = database.retrieve_queue.iter().position(|&r| r == uid).unwrap();
        database.retrieve_queue.remove(index);
        database.count = database.count + 1;
        database.completed_queue.push(uid);
        let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
        create_sealeddata_for_db(database, &mut sealed_log_in);
        save_sealed_data(DATAFILE, &sealed_log_in);
        return sgx_status_t::SGX_SUCCESS;
    }
}

#[no_mangle]
pub extern "C" fn audit(out_serialized_ptr: * mut u8, max_size: usize, out_ptr_size: *mut usize) -> sgx_status_t {
    println!("audit enclave");

    let database: Database = match unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let mut audit_db = AuditDatabase {
        timestamp: 0,
        retrieve_count: 0,
        users: Vec::new(),
        retrieve: Vec::new(),
    };

    audit_db.timestamp = database.timestamp;
    audit_db.retrieve_count = database.count;
    for (_, entry) in database.data.iter() {
        println!("add users uid {:?}", entry.uid);
        audit_db.users.push(entry.encrypted_secret.data().to_vec());
        println!("end add users uid {:?}", entry.uid);
    }
    for uid in database.completed_queue {
        match database.data.get(&uid) {
            Some(e) => {
                println!("add users uid {:?}", e.uid);
                audit_db.retrieve.push(e.encrypted_secret.data().to_vec());
            }
            None => {}
        };
    }

    let encoded_vec = match serde_cbor::to_vec(&audit_db){
        Ok(x) => x,
        Err(e) => {
            println!("Error to_vec {}", e);
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    println!("encoded_vec {:?}", encoded_vec);
    println!("audit_db {:?}", audit_db);

    let ptr = encoded_vec.as_ptr();

    if encoded_vec.len() > max_size {
        println!("output buffer len is too small {} > {}", encoded_vec.len(), max_size);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    unsafe { std::ptr::copy(&mut encoded_vec.len(), out_ptr_size, 1) }
    unsafe { println!("ptr_size {:?}", *out_ptr_size) }
    unsafe { std::ptr::copy(ptr, out_serialized_ptr, *out_ptr_size) }
    let output = unsafe { slice::from_raw_parts(ptr, *out_ptr_size) };
    println!("output {:?}", output);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn public_key(out_encoded_public_key_n: &mut [u8; crypto::SECRET_DATA_LEN], out_encoded_public_key_e: &mut [u8; 4]) -> sgx_status_t {
    let database = match unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    let pk = database.rsa_key.output_public_key();
    println!("pk.get_n().data().len() {}", pk.get_n().len());
    if crypto::SECRET_DATA_LEN != pk.get_n().len() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    *out_encoded_public_key_n = pk.get_n();
    *out_encoded_public_key_e = pk.get_e();
    sgx_status_t::SGX_SUCCESS
}

fn build_database(rsa_key: crypto::RSAKeyPair) -> Database {
    Database {
        data: HashMap::new(),
        retrieve_queue: Vec::new(),
        completed_queue: Vec::new(),
        count: 0,
        rsa_key: rsa_key,
        timestamp: time::get_timestamp(),
    }
}

fn build_entry(uid: u32, secret: &[u8; crypto::SECRET_DATA_LEN], len: usize,  encrypted_secret: &[u8; crypto::SECRET_DATA_LEN]) -> Entry {
    Entry {
        uid: uid,
        secret: crypto::SecretData::new_data(secret, len),
        encrypted_secret: crypto::SecretData::new_data(encrypted_secret, crypto::SECRET_DATA_LEN),
        count: 0,
        last_retreive: 0,
    }
}

fn create_sealeddata_for_db(db: Database, sealed_log_out: &mut [u8; SEAL_LOG_SIZE]) -> sgx_status_t {

    let encoded_vec = serde_cbor::to_vec(&db).unwrap();
    let encoded_slice = encoded_vec.as_slice();
    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            println!("Err(ret) {:?}", ret);
            return ret;
        },
    };

    let sealed_log = sealed_log_out.as_mut_ptr();

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, SEAL_LOG_SIZE as u32);
    if opt.is_none() {
        println!("opt.is_none()");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_status_t::SGX_SUCCESS
}

fn recover_db_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> Result<Database, Error> {

    let sealed_data = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size).ok_or(Error::SliceError)?;
    let unsealed_data = sealed_data.unseal_data().map_err(|err| Error::UnsealError(err))?;
    let encoded_slice = unsealed_data.get_decrypt_txt();
    let mut data: Database = serde_cbor::from_slice(encoded_slice).unwrap();
    let curr_time = time::get_timestamp();
    let mut time_since_reset = curr_time - data.timestamp;
    if  time_since_reset >= RESET_SECONDS {
        println!("time_since_reset {}", time_since_reset);
        data.count = 0;
        while time_since_reset >= RESET_SECONDS {
            time_since_reset = curr_time - data.timestamp;
            data.timestamp = data.timestamp + RESET_SECONDS;
        }
        println!("reset timestamp to {}", data.timestamp);
    }
    println!("recovered db {:?}", data);

    Ok(data)
}

fn unseal_db_wrapper() -> Result<Database, Error> {
    let p = DATAFILE;
    let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
    match load_sealed_data(&p, &mut sealed_log_out) {
        Ok(_) => {
            let sealed_log = sealed_log_out.as_mut_ptr();
            let data = recover_db_for_serializable(sealed_log, SEAL_LOG_SIZE as u32)?;
            Ok(data)
        },
        Err(err) => {
            Err(err)
        }
    }
}

fn save_sealed_data(path: &str, sealed_data: &[u8]) -> sgx_status_t {
    let opt = File::create(path);
    if opt.is_ok() {
        println!("Created file => {} ", path);
        let mut file = opt.unwrap();
        let result = file.write_all(&sealed_data);
        if result.is_ok() {
            println!("success writing to file! ");
            return sgx_status_t::SGX_SUCCESS;
        } else {
            println!("error writing to file! ");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
    sgx_status_t::SGX_SUCCESS
}

fn load_sealed_data(path: &str, sealed_data: &mut [u8]) -> Result<(), Error> {
    let mut file = match File::open(path) {
        Err(_why) => return Err(Error::SerializeError),
        Ok(file) => file,
    };
    println!("Created file => {} ", path);

    let result = file.read(sealed_data);
    if result.is_ok() {
        println!("success reading from file! ");
        return Ok(());
    } else {
        println!("error reading from file! ");
        return Err(Error::SerializeError);
    }
}

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
