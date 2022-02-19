use crypto;
use time;
use merkletree;

use std::vec::Vec;
use std::collections::HashMap;
use std::string::String;
use std::untrusted::fs::File;
use std::io::{self, Read, Write};

use sgx_types::*;
use sgx_tseal::{SgxSealedData};
use sgx_types::marker::ContiguousMemory;

pub const DATAFILE: &str = "data.sealed";
pub const SEAL_LOG_SIZE: usize = 4096*2;     // Maximum data can seal in bytes -> smaller than "HeapMaxSize" in Enclave.config.xml
pub const RESET_SECONDS: u64 = 86400*24000; //24 hours time between database is reset
// pub const RESET_SECONDS: u64 = 60;
pub const MAX_RETREIVE: u64 = 2;
pub const COUNTDOWN_TIME: u64 = 5;//24*60*60;


pub enum Error {
    SliceError,
    UnsealError(sgx_status_t),
    SerializeError,
    Other
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
   pub count: u64,
   pub cancel_key: crypto::ECCPublicKey,
   pub secret: crypto::SecretData,
   pub encrypted_secret: crypto::SecretData,
   pub uid: u32,
   pub last_retrieve: u64, //time when retreive can be completed
}

pub struct RetreiveEntry
{
    pub uid: u32,
    pub countdown: u64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AuditEntry {
    // pub enc_uid: Vec<u8>, TODO
    pub uid: u32,
    pub cancel_key: crypto::ECCPublicKey,
    pub countdown: u64,
    pub retrieve_count: u64
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Database {
    pub count: u64,
    pub data: HashMap<u32, Entry>,
    pub retrieve_queue: HashMap<u32, u64>, //all started and not completed retrieves
    pub completed_queue: Vec<u32>, //completed on that day
    pub rsa_key: crypto::RSAKeyPair,
    pub timestamp: u64, //timestamp of creation of database. when updated set to timestamp + reset_time
    pub max_count: u64,
    pub wait_time: u64,
    pub reset_time: u64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AuditDatabase {
    pub timestamp: u64,
    pub retrieve_count: u64,
    // pub users: Vec<Vec<u8>>,
    // pub retrieve: Vec<Vec<u8>>,
    pub tree: merkletree::MerkleTree,
    pub max_count: u64,
    pub wait_time: u64,
    pub reset_time: u64,
}

pub fn build_database(rsa_key: crypto::RSAKeyPair) -> Database {
    Database {
        data: HashMap::new(),
        retrieve_queue: HashMap::new(),
        completed_queue: Vec::new(),
        count: 0,
        rsa_key: rsa_key,
        timestamp: time::get_timestamp(),
        max_count: MAX_RETREIVE,
        wait_time: COUNTDOWN_TIME,
        reset_time: RESET_SECONDS,
    }
}

pub fn build_entry(uid: u32, cancel_key: crypto::ECCPublicKey, secret: &[u8; crypto::SECRET_DATA_LEN], secret_len: usize,  encrypted_secret: &[u8; crypto::SECRET_DATA_LEN]) -> Entry {
    Entry {
        uid: uid,
        secret: crypto::SecretData::new_data(secret, secret_len),
        cancel_key: cancel_key,
        encrypted_secret: crypto::SecretData::new_data(encrypted_secret, crypto::SECRET_DATA_LEN),
        count: 0,
        last_retrieve: 0,
    }
}

pub fn create_sealeddata_for_db(db: Database, sealed_log_out: &mut [u8; SEAL_LOG_SIZE]) -> sgx_status_t {

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

pub fn unseal_db_wrapper() -> Result<Database, Error> {
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

pub fn save_sealed_data(path: &str, sealed_data: &[u8]) -> sgx_status_t {
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

fn recover_db_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> Result<Database, Error> {

    let sealed_data = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size).ok_or(Error::SliceError)?;
    let unsealed_data = sealed_data.unseal_data().map_err(|err| Error::UnsealError(err))?;
    let encoded_slice = unsealed_data.get_decrypt_txt();
    let mut data: Database = serde_cbor::from_slice(encoded_slice).unwrap();
    let curr_time = time::get_timestamp();
    println!("curr_time {}  data.timestamp {}", curr_time, data.timestamp);
    let mut time_since_reset = data.timestamp - curr_time;
    if  time_since_reset >= data.reset_time {
        println!("time_since_reset {} {}", time_since_reset,  data.reset_time);
        data.count = 0;
        while time_since_reset >= data.reset_time {
            time_since_reset = data.timestamp - curr_time;
            data.timestamp = data.timestamp + data.reset_time;
        }

        println!("reset timestamp to {}", data.timestamp);
         data.completed_queue = Vec::new();
    }
    println!("recovered db {:?}", data);

    Ok(data)
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
