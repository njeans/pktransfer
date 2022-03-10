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
extern crate http_req;
extern crate ring;
extern crate base64;

mod crypto;
mod data;
mod time;
mod merkletree;

use std::string::String;
use std::vec::Vec;
use std::io::{self, Read, Write};
use std::slice;
use std::untrusted::fs::File;

use sgx_types::*;
use sgx_tcrypto::*;
use ring::{aead, error};


pub const SYMMETRIC_KEY_LEN: usize = 32 + aead::NONCE_LEN;
pub const UID_SIZE: usize = 4;

#[no_mangle]
pub extern "C" fn init_db(out_encoded_public_key_n: &mut [u8; crypto::SECRET_DATA_LEN], out_encoded_public_key_e: &mut [u8; 4]) -> sgx_status_t {
    println!("Init db");

    match File::open(data::DATAFILE) {
        Ok(_) => {
            println!("data::DATAFILE exists");
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

    let database = data::build_database(rsa_key);
    let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
    let p = data::DATAFILE;

    match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
        sgx_status_t::SGX_SUCCESS => {
            return data::save_sealed_data(&p, &sealed_log_in);
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}

#[no_mangle]
pub extern "C" fn signup(encrypted_secret_ptr: *const u8, secret_size: usize, cancel_public_key_x: &mut [u8; 32], cancel_public_key_y: &mut [u8; 32]) -> sgx_status_t {
    println!("sign up");
    if secret_size != crypto::SECRET_DATA_LEN {
        println!("secret_size {} must be {}", secret_size, crypto::SECRET_DATA_LEN);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let encrypted_secret_slice = unsafe { slice::from_raw_parts(encrypted_secret_ptr, secret_size) };
    println!("encrypted_secret_slice {:?}", encrypted_secret_slice);

    let mut database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
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
            println!("Error decrypt encrypted_secret {:}",e);
            return e;
        }
    };

    let (uid_entry, _) = decrypted_secret.split_at(UID_SIZE);
    println!("uid_entry {:?}",uid_entry);
    let mut uid_arr: [u8; UID_SIZE] = Default::default();
    uid_arr.copy_from_slice(uid_entry);
    let uid = u32::from_be_bytes(uid_arr);
    println!("uid {:?}",uid);

    let cancel_key = crypto::ECCPublicKey{x: *cancel_public_key_x, y:*cancel_public_key_y};

    if database.data.contains_key(&uid) {
        println!("Error uid already found");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    } else {

        let entry = data::build_entry(uid, cancel_key, &decrypted_secret, decrypted_secret_len, &encrypted_secret);
        database.data.insert(uid, entry);
        let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
        let p = data::DATAFILE;
        println!("final database {:?}", database);
        match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
            sgx_status_t::SGX_SUCCESS => {
                println!("data::save_sealed_data(&p, &sealed_log_in);");
                return data::save_sealed_data(&p, &sealed_log_in);
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
    println!("host_retrieve uid {:?}",uid);

    let mut database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    if !database.data.contains_key(&uid) {
        println!("Error uid not found");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    if database.retrieve_queue.contains_key(&uid) {
      return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    } else {
        let curr_time = time::get_timestamp();
        if curr_time == 0 {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        database.retrieve_queue.insert(uid,curr_time);
        let mut entry: &mut data::Entry  = database.data.get_mut(&uid).unwrap();
        entry.last_retrieve = curr_time;

        let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
        let p = data::DATAFILE;
        println!("final database {:?}", database);
        match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
            sgx_status_t::SGX_SUCCESS => {
                return data::save_sealed_data(&p, &sealed_log_in);
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

    let mut database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    if database.count >= database.max_count {
        println!("database.count {} >= database.max_count {}", database.count, database.max_count);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let mut entry: &mut data::Entry  = match database.data.get_mut(&uid) {
        Some(x) => x,
        None => {
            println!("Error cannot find uid {:?} {:?}", uid, database.data.contains_key(&uid));
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };
    if entry.count > database.max_count {
        println!("Error entry count too large {}", entry.count);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    if !database.retrieve_queue.contains_key(&uid) {
        println!("Error cannot find uid in retrieve_queue");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    if time::get_timestamp() - database.retrieve_queue.get(&uid).unwrap() < database.wait_time {
        println!("Error countdown not completed");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

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
    entry.last_retrieve = 0;
    database.retrieve_queue.remove(&uid);
    database.count = database.count + 1;
    println!("database.count {:?}", database.count);
    database.completed_queue.push(uid);
    let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
    data::create_sealeddata_for_db(database, &mut sealed_log_in);
    data::save_sealed_data(data::DATAFILE, &sealed_log_in);
    return sgx_status_t::SGX_SUCCESS;

}

#[no_mangle]
pub extern "C" fn cancel(uid: u32, data_ptr: *const u8, data_size: usize, cancel_sig_x: &mut [u8; 32], cancel_sig_y: &mut [u8; 32]) -> sgx_status_t {
    println!("cancel enclave");
    // println!("cancel uid {:?}",uid);
    if data_size != SGX_SHA256_HASH_SIZE {
        println!("hash_data_size {} must be {}", data_size, SGX_SHA256_HASH_SIZE);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let data_slice = unsafe { slice::from_raw_parts(data_ptr, data_size) };
    println!("data_slice {:?}", data_slice);

    let mut database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    if !database.data.contains_key(&uid) {
        println!("Error uid not found in data");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    if !database.retrieve_queue.contains_key(&uid) {
        println!("Error uid not found in retrieve_queue");
      return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    } else {
        let mut curr_entry: &mut data::Entry  = database.data.get_mut(&uid).unwrap();
        let cancel_sig = crypto::ECCSig{x: *cancel_sig_x, y:*cancel_sig_y};
        let mut message_hash: [u8; SGX_SHA256_HASH_SIZE] =  Default::default();
        message_hash.copy_from_slice(data_slice);
        match crypto::verify_ecdsa(&message_hash, cancel_sig, curr_entry.cancel_key) {
            true => {},
            false => {
                println!("Error verifying signature");
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
        println!("Cancel signature verified");

        match database.retrieve_queue.remove(&uid) {
            None => {
                println!("Error removing entry from retrieve_queue");
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
            Some(_) => {}
        }

        let mut entry: &mut data::Entry  = database.data.get_mut(&uid).unwrap();
        entry.last_retrieve = 0;

        let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
        let p = data::DATAFILE;
        println!("final database {:?}", database);
        match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
            sgx_status_t::SGX_SUCCESS => {
                return data::save_sealed_data(&p, &sealed_log_in);
            }
            _ => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn audit(out_serialized_ptr: * mut u8, max_size: usize, out_ptr_size: *mut usize) -> sgx_status_t {
    println!("audit enclave");

    let database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let mut audit_db = data::AuditDatabase {
        timestamp: 0,
        retrieve_count: 0,
        // users: Vec::new(),
        // retrieve: Vec::new(),
        tree: merkletree::MerkleTree::new(),
        max_count: 0,
        wait_time: 0,
        reset_time: 0,
    };

    let mut audit_entries = Vec::new();

    audit_db.timestamp = database.timestamp;
    audit_db.retrieve_count = database.count;
    audit_db.max_count = database.max_count;
    audit_db.wait_time = database.wait_time;
    audit_db.reset_time = database.reset_time;

    for (_, entry) in database.data.iter() {
        // audit_db.users.push(entry.encrypted_secret.data().to_vec());
        println!("add users uid {:?}", entry.uid);
        let ae = data::AuditEntry{
            // enc_uid: entry.encrypted_secret.data().to_vec(), TODO
            uid: entry.uid,
            countdown: entry.last_retrieve,
            retrieve_count: entry.count,
            cancel_key: entry.cancel_key,// TODO
        };
        audit_entries.push(ae);
    }
    // for uid in database.completed_queue {
    //     match database.data.get(&uid) {
    //         Some(e) => {
    //             println!("add users uid {:?}", e.uid);
    //             audit_db.retrieve.push(e.encrypted_secret.data().to_vec());
    //         }
    //         None => {}
    //     };
    // }

    audit_db.tree = match merkletree::MerkleTree::build(&audit_entries){
        Ok(x) => x,
        Err(e) => {
            println!("Error merkletree::MerkleTree::build {}", e);
            return e;
        }
    };

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
    let database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
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

#[no_mangle]
pub extern "C" fn update_max_retrieve(max_retrieve_count: u64) -> sgx_status_t {
    let mut database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    database.max_count = max_retrieve_count;
    let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
    let p = data::DATAFILE;
    println!("final database {:?}", database);
    match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
        sgx_status_t::SGX_SUCCESS => {
            return data::save_sealed_data(&p, &sealed_log_in);
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}

#[no_mangle]
pub extern "C" fn update_retrieve_wait_time(wait_time: u64) -> sgx_status_t {
    let mut database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    database.wait_time = wait_time;
    let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
    let p = data::DATAFILE;
    println!("final database {:?}", database);
    match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
        sgx_status_t::SGX_SUCCESS => {
            return data::save_sealed_data(&p, &sealed_log_in);
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}

#[no_mangle]
pub extern "C" fn update_reset_time(reset_seconds: u64) -> sgx_status_t {
    let mut database: data::Database = match data::unseal_db_wrapper() {
        Ok(x) => x,
        Err(_) => {
            println!("Error data::unseal_db_wrapper");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };
    database.reset_time = reset_seconds;
    let mut sealed_log_in = [0u8; data::SEAL_LOG_SIZE];
    let p = data::DATAFILE;
    println!("final database {:?}", database);
    match data::create_sealeddata_for_db(database, &mut sealed_log_in) {
        sgx_status_t::SGX_SUCCESS => {
            return data::save_sealed_data(&p, &sealed_log_in);
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}
