
use std::vec::Vec;
use std::string::String;

use sgx_types::*;
use sgx_tcrypto::*;

use ring::{aead, error, signature};

pub const SECRET_DATA_LEN: usize = 256;
pub const RETREIVE_SECRET_LEN: usize = 364;
//required because Serialize is only implemented for 32 length slice
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct SecretData {
    data: [[u8; 32]; 8],
    len: usize,
}

impl SecretData {
    pub fn new() -> SecretData {
        SecretData{
            data: [[0; 32]; 8],
            len: SECRET_DATA_LEN,
        }
    }

    pub fn new_data(secret: &[u8; SECRET_DATA_LEN], len: usize) -> SecretData {
        let mut secret_str: [[u8; 32]; 8] = Default::default();
        secret_str[0].copy_from_slice(&secret[0 .. 32]);
        secret_str[1].copy_from_slice(&secret[32 .. 64]);
        secret_str[2].copy_from_slice(&secret[64 .. 96]);
        secret_str[3].copy_from_slice(&secret[96 .. 128]);
        secret_str[4].copy_from_slice(&secret[128 .. 160]);
        secret_str[5].copy_from_slice(&secret[160 .. 192]);
        secret_str[6].copy_from_slice(&secret[192 .. 224]);
        secret_str[7].copy_from_slice(&secret[224 .. 256]);
        SecretData{
            data: secret_str,
            len: len
        }
    }

    // pub fn data(&self) -> String {
    //     String::from_utf8((&self.data_256()[0..self.len]).to_vec()).unwrap()
    // }

    pub fn data(&self) -> [u8; SECRET_DATA_LEN] {
        use std::mem::transmute;
        unsafe { transmute(self.data) }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct RSAKeyPair {
    mod_size: i32,
    exp_size: i32,
    n: Vec<u8>,
    d: Vec<u8>,
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    dmp1: Vec<u8>,
    dmq1: Vec<u8>,
    iqmp: Vec<u8>,
}

impl RSAKeyPair {
    pub fn new() -> RSAKeyPair {
        RSAKeyPair{
            mod_size: 0,
            exp_size: 0,
            n: Vec::new(),
            d: Vec::new(),
            e: Vec::new(),
            p: Vec::new(),
            q: Vec::new(),
            dmp1: Vec::new(),
            dmq1: Vec::new(),
            iqmp: Vec::new(),
        }
    }

    pub fn public_key(&self, pubkey: &SgxRsaPubKey) -> sgx_status_t {
        let result = pubkey.create(self.mod_size, self.exp_size, self.n.as_slice(), self.e.as_slice());
        match result {
            Err(x) => return x,
            Ok(()) => {}
        };
        sgx_status_t::SGX_SUCCESS
    }

    pub fn private_key(&self,  privkey: &SgxRsaPrivKey) -> sgx_status_t {
        let result = privkey.create(
            self.mod_size,
            self.exp_size,
            self.e.as_slice(),
            self.p.as_slice(),
            self.q.as_slice(),
            self.dmp1.as_slice(),
            self.dmq1.as_slice(),
            self.iqmp.as_slice(),
        );
        match result {
            Err(x) => return x,
            Ok(()) => {}
        };
        sgx_status_t::SGX_SUCCESS
    }

    pub fn output_public_key(&self) -> RSAPublicKey {
        let mut n_vec = [0; SECRET_DATA_LEN];
        n_vec.copy_from_slice(&self.n[0..SECRET_DATA_LEN]);
        let n_val = SecretData::new_data(&n_vec, 256);
        let mut e_vec = [0; 4];
        e_vec.copy_from_slice(&self.e[0..4]);

        RSAPublicKey{
            mod_size: self.mod_size,
            exp_size: self.exp_size,
            n: n_val,
            e: e_vec,
        }

    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct RSAPublicKey {
    mod_size: i32,
    exp_size: i32,
    n: SecretData,
    e: [u8; 4],
}

impl RSAPublicKey {
    pub fn new() -> RSAPublicKey {
        RSAPublicKey{
            mod_size: 0,
            exp_size: 0,
            n: SecretData::new(),
            e: [0; 4],
        }
    }

    pub fn build(n: [u8; 256], e: [u8; 4]) -> RSAPublicKey {
        let mut public_key = RSAPublicKey{
            mod_size: 256,
            exp_size: 4,
            n: SecretData::new_data(&n, 256 as usize),
            e: [0; 4],
        };
        public_key.e.copy_from_slice(&e);
        return public_key;
    }

    pub fn public_key(&self, pubkey: &SgxRsaPubKey) -> sgx_status_t {
        let result = pubkey.create(self.mod_size, self.exp_size, &self.n.data(), &self.e);
        match result {
            Err(x) => return x,
            Ok(()) => {}
        };
        sgx_status_t::SGX_SUCCESS
    }

    pub fn get_n(&self) -> [u8; 256] {
        self.n.data()
    }


    pub fn get_e(&self) -> [u8; 4] {
        self.e
    }
}

pub fn build_rsa_key(rsa_key: &mut RSAKeyPair, public_key: &mut RSAPublicKey) -> sgx_status_t {
    println!("build_rsa_key");
    let mod_size: i32 = 256;
    let exp_size: i32 = 4;
    let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut e: Vec<u8> = vec![1, 0, 0, 1];
    let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];

    let result = rsgx_create_rsa_key_pair(
        mod_size,
        exp_size,
        n.as_mut_slice(),
        d.as_mut_slice(),
        e.as_mut_slice(),
        p.as_mut_slice(),
        q.as_mut_slice(),
        dmp1.as_mut_slice(),
        dmq1.as_mut_slice(),
        iqmp.as_mut_slice(),
    );

    match result { Err(x) => {
            return x;
        }
        Ok(()) => {}
    }

    rsa_key.mod_size = mod_size;
    rsa_key.exp_size = exp_size;
    rsa_key.n = n.clone();
    rsa_key.d = d;
    rsa_key.e = e.clone();
    rsa_key.p = p;
    rsa_key.q = q;
    rsa_key.dmp1 = dmp1;
    rsa_key.dmq1 = dmq1;
    rsa_key.iqmp = iqmp;
    public_key.mod_size = mod_size;
    public_key.exp_size = exp_size;
    println!("n {:?}", n);
    println!("e {:?}", e);

    let mut n_slice = [0; 256];
    n_slice.copy_from_slice(&n[0..256]);
    public_key.n = SecretData::new_data(&n_slice, 256 as usize);
    public_key.e.copy_from_slice(&e[0..4]);
    sgx_status_t::SGX_SUCCESS
}

pub fn build_aead_key(key_bytes: [u8; 32], nonce_bytes: [u8; aead::NONCE_LEN]) -> Result<aead::SealingKey<OneNonceSequence>, ring::error::Unspecified> {
    let key = match aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes){
        Ok(x) => x,
        Err(e) => {
            return Err(e);
        }
    };
    let seal_nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let nonce_sequence = OneNonceSequence::new(seal_nonce);
    let output_key: aead::SealingKey<OneNonceSequence> = aead::BoundKey::new(key, nonce_sequence);
    Ok(output_key)
}

pub fn decrypt_rsa(plaintext: &mut [u8], plaintext_len: &mut usize, ciphertext: &[u8], privkey: SgxRsaPrivKey) -> sgx_status_t {
    let ret = privkey.decrypt_sha256(plaintext,
                                    plaintext_len,
                                    ciphertext);
    match ret {
        Ok(()) => {
            println!("rsa plaintext_len: {:?}", plaintext_len);
        },
        Err(x) => {
            return x;
        },
    };
    sgx_status_t::SGX_SUCCESS
}

pub fn encrypt_rsa(plaintext: &[u8], ciphertext: &mut [u8], pubkey: SgxRsaPubKey) -> sgx_status_t {
    println!("crypto::encrypt_rsa {:?}",plaintext.len());
    let mut ciphertext_len: usize = ciphertext.len();
    let ret = pubkey.encrypt_sha256(ciphertext,
                                    &mut ciphertext_len,
                                    plaintext);
    match ret {
        Ok(_) => {
            println!("rsa ciphertext_len: {:?}", ciphertext_len);
        },
        Err(e) => {
            println!("Error rsa {:?}", e);
            return e;
        },

    };
    sgx_status_t::SGX_SUCCESS
}

pub fn encrypt_aead(ciphertext: &mut Vec<u8>, plaintext: &[u8; SECRET_DATA_LEN], key: &mut aead::SealingKey<OneNonceSequence>) -> Result<(), ring::error::Unspecified> {
    let aad = vec![];
    ciphertext.copy_from_slice(&plaintext[0..SECRET_DATA_LEN]);
    match key.seal_in_place_append_tag(aead::Aad::from(&aad[..]), ciphertext) {
        Ok(_) => {
            return Ok(())
        }
        Err(e) => {
            return Err(e);
        }
    }
}

pub fn verify_ecdsa(message_hash: &[u8; SGX_SHA256_HASH_SIZE], sig: ECCSig, pubkey: ECCPublicKey) -> bool{

    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let mut hash: sgx_sha256_hash_t = *message_hash;
    let mut public = sgx_ec256_public_t::default();
    public.gx = pubkey.x;
    public.gy = pubkey.y;

    let mut signature = sgx_ec256_signature_t::default();
    let mut tmp = [0_u8; 4];
    for n in 0..8 {
        tmp.copy_from_slice(&sig.x[(n*4)..(n*4+4)]);
        signature.x[7-n] = u32::from_le_bytes(tmp);
        tmp.copy_from_slice(&sig.y[(n*4)..(n*4+4)]);
        signature.y[7-n] = u32::from_le_bytes(tmp);
    }

    println!("test verify_ecdsa public \n\t{:?}\n\t{:?}",public.gx,public.gy);
    println!("test verify_ecdsa message_hash \n\t{:?}",message_hash);
    println!("test verify_ecdsa signature \n\t{:?}\n\t{:?}", signature.x,signature.y);

    match ecc_handle.ecdsa_verify_hash(&hash,&public,&signature) {
        Ok(r) => {
            println!("verify_ecdsa result {:?}",r);
            r
        },
        Err(e) => {
            println!("error verify_ecdsa {:?}",e);
            false
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct ECCPublicKey {
    pub x: [u8; SGX_ECP256_KEY_SIZE],
    pub y: [u8; SGX_ECP256_KEY_SIZE],
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct ECCSig {
    pub x: [u8; SGX_ECP256_KEY_SIZE],
    pub y: [u8; SGX_ECP256_KEY_SIZE],
}

pub struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}
