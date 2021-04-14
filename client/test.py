import requests
import json
from base64 import b64encode, b64decode
import Crypto
from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

url = "http://localhost:8000"
pk_file = "enclave_public_key.pem"
uid_size = 4
max_count = 5

def encrypt_rsa(msg_plaintext, pem_filename):
    key = RSA.importKey(open(pem_filename).read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)
    secret = cipher.encrypt(msg_plaintext)
    data = int_to_bytes(int.from_bytes(secret, 'big', signed=False), 256)
    return data

def decrypt_rsa(msg_plaintext, pem_filename):
    key = RSA.importKey(open(pem_filename).read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)
    secret = cipher.encrypt(msg_plaintext)
    data = int_to_bytes(int.from_bytes(secret, 'big', signed=False), 256)
    return data

def int_to_bytes(val, num_bytes):
    return [(val & (0xff << pos*8)) >> pos*8 for pos in reversed(range(num_bytes))]

def get_pk():
    get_pub_key_req = requests.get(url + '/public_key')
    if get_pub_key_req.status_code != 200:
        print("get_pub_key_req status_code != 200:", get_pub_key_req.status_code, get_pub_key_req.content)
        exit(1)
    pk_data = json.loads(get_pub_key_req.content)
    n_split = pk_data["n"]
    n_arr = n_split[0] + n_split[1] + n_split[2] + n_split[3] + n_split[4] + n_split[5] + n_split[6] + n_split[7]
    n = int.from_bytes(bytearray(n_arr), "little")
    e = int.from_bytes(bytearray(pk_data["e"]), "little")
    pub = RSA.construct((n,e))
    pk_bytes = pub.export_key('PEM')
    with open(pk_file, "wb") as f:
        f.write(pk_bytes)

def signup(uid, data):
    uid_chr="".join([chr(x) for x in int_to_bytes(uid,4)])
    message = (uid_chr+data).encode('utf8')
    data = encrypt_rsa(message, pk_file)
    signup_data = {"secret":data}
    signup_req = requests.post(url + "/signup", json=signup_data, headers={"Content-Type": "application/json"})
    if signup_req.status_code != 200:
        print("signup_req status_code != 200:", signup_req.status_code, signup_req.content)
        exit(1)
    return data

def host_ret(uid):
    host_ret_data = {"uid":uid}
    host_ret_req = requests.post(url + "/host", json=host_ret_data, headers={"Content-Type": "application/json"})
    if host_ret_req.status_code != 200:
        print("host_ret_req status_code != 200:", host_ret_req.status_code, host_ret_req.content)
        exit(1)

def user_ret(uid, expected):
    key = get_random_bytes(32)
    cipher = ChaCha20_Poly1305.new(key=key)

    key_bytes = list(bytearray(b64encode(key)))
    nonce_bytes = list(bytearray(b64encode(cipher.nonce)))
    message_bytes = key_bytes+nonce_bytes
    message = "".join([chr(x) for x in message_bytes])
    data = encrypt_rsa(b64encode(key)+b64encode(cipher.nonce), pk_file)

    user_ret_data = {"uid":uid, "secret":data}
    user_ret_req = requests.post(url + "/user", json=user_ret_data, headers={"Content-Type": "application/json"})
    if user_ret_req.status_code != 200:
        print("user_ret_req status_code != 200:", user_ret_req.status_code, user_ret_req.content)
        exit(1)

    return_data = b64decode(user_ret_req.content)
    ciphertext = bytes(return_data[:-16])
    tag = bytes(return_data[-16:])
    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8').rstrip(chr(0))
    uid_chr="".join([chr(x) for x in int_to_bytes(uid,4)])
    print("result", str([ord(x) for x in plaintext]),str([ord(x) for x in uid_chr+expected]))
    assert(str(plaintext) == str(uid_chr+expected))

def audit(users=None, retreivals=None):
    get_audit_req = requests.get(url + '/audit')
    if get_audit_req.status_code != 200:
        print("get_audit_req status_code != 200:", get_audit_req.status_code, get_audit_req.content)
        exit(1)
    audit_data = json.loads(get_audit_req.content)
    print("audit_data",audit_data)
    assert(audit_data["retrieve_count"] <= max_count)

    if users is not None:
        for secret in users:
            # print("\t",secret in audit_data["users"], secret)
            assert(secret in audit_data["users"])

    if retreivals is not None:
        for secret in retreivals:
            # print("\t",secret in audit_data["users"], secret)
            assert(secret in audit_data["retrieve"])


get_pk()
test_uid = 15
test_data = "hello1"
secret5 = signup(test_uid,test_data)
host_ret(test_uid)
user_ret(test_uid,test_data)
audit(users=[secret5], retreivals=[secret5])
test_uid = 16
test_data = "hello2"
secret6 = signup(test_uid,test_data)
audit(users=[secret5, secret6], retreivals=[secret5])
print("success")
