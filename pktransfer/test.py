import requests
import json
from base64 import b64encode, b64decode
import Crypto
from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import time
import math

url = "http://localhost:8000"
pk_file = "enclave_public_key.pem"
uid_size = 4
max_count = 2

def encrypt_rsa(msg_plaintext, pem_filename):
    key = RSA.importKey(open(pem_filename).read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)
    secret = cipher.encrypt(msg_plaintext)
    # data = int_to_bytes(int.from_bytes(secret, 'big', signed=False), 256)
    return secret

def decrypt_rsa(msg_plaintext, pem_filename):
    key = RSA.importKey(open(pem_filename).read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)
    secret = cipher.encrypt(msg_plaintext)
    data = int_to_bytes(int.from_bytes(secret, 'big', signed=False), 256)
    return data

def int_to_bytes(val, num_bytes):
    return [(val & (0xff << pos*8)) >> pos*8 for pos in reversed(range(num_bytes))]

def get_number_hex(values):
    total = 0
    for val in reversed(values):
        total = (total << 8) + val
    return hex(total)

def get_number(values):
    total = 0
    for val in values:#reversed(values):
        total = (total << 8) + val
    return total

def get_number_trunc(values):
    h=get_number_hex(values)
    return str(h[:10])+"..."


class Tree(object):
    def __init__(self):
        self.left = None
        self.right = None
        self.data = None

    def __str__(self):
        return str(self.data)

def helper(nodes,pos,curr):
    level = math.floor(math.log(pos,2))
    left_pos = 2**(level+1) + (pos-2**level) * 2
    right_pos = 2**(level+1) + (pos-2**level) * 2 + 1
    # print("pod",left_pos,right_pos,len(nodes))
    if left_pos <= len(nodes):
        curr.left = Tree()
        curr.left.data = nodes[left_pos-1]
        # print("left of ",curr.data,": ",curr.left)
        helper(nodes,left_pos,curr.left)
    if right_pos <= len(nodes):
        curr.right =  Tree()
        curr.right.data = nodes[right_pos-1]
        # print("right of ",curr.data,": ",curr.right)
        helper(nodes,right_pos,curr.right)


def make_tree(nodes):
    root = Tree()
    pos = 1
    root.data = nodes[0]
    # print("root",roxsot)
    helper(nodes,pos,root)
    # print(str(root))
    return root

def print_tree(node, level=0, right=False):
    if node != None:
        print_tree(node.left, level + 1)
        if right:
            print("\t" * level + '->', node.data)
            # print("\t" * level + '\\', node.data)
        else:
            # print("\t" * level + '/', node.data)
            print("\t" * level + '->', node.data)
        print_tree(node.right, level + 1, True)

def helper_index(curr_path,leaf_index):
    if leaf_index == 0:
        return curr_path
    if leaf_index % 2 == 0:
        leaf_level =  math.floor(math.log(leaf_index+1,2))
        parent_level = leaf_level - 1
        parent_index = (leaf_index - (2**leaf_level))/2 - (2**parent_level)
        curr_path.append(leaf_index+1)
        curr_path.append(parent_index)
        helper_index(curr_path,parent_index)
    else:
        print(leaf_index+1)
        print(math.log(leaf_index+1,2))
        print(math.floor(math.log(leaf_index+1,2)))

        leaf_level =  math.floor(math.log(leaf_index+1,2))
        parent_level = leaf_level - 1
        parent_index = (leaf_index - (2**leaf_level)-1)/2 - (2**parent_level)
        curr_path.append(leaf_index-1)
        curr_path.append(parent_index)
        helper_index(curr_path,parent_index)

def get_path(root,leaf_index):
    path= [leaf_index]
    helper_index(path,leaf_index)
    print(path)


def get_pk():
    get_pub_key_req = requests.get(url + '/public_key')
    if get_pub_key_req.status_code != 200:
        print("get_pub_key_req status_code != 200:", get_pub_key_req.status_code, get_pub_key_req.content)
        return
    pk_data = json.loads(get_pub_key_req.content)
    n = int.from_bytes(bytearray(b64decode(pk_data["n"])), "little")
    e = int.from_bytes(bytearray(b64decode(pk_data["e"])), "little")
    pub = RSA.construct((n,e))
    pk_bytes = pub.export_key('PEM')
    with open(pk_file, "wb") as f:
        f.write(pk_bytes)
    print("success download enclave public key into",pk_file,"\n")

def signup(uid, secret_data):
    uid_chr= "".join([chr(x) for x in int_to_bytes(uid,4)])
    message = (uid_chr+secret_data).encode('utf8')
    data = encrypt_rsa(message, pk_file)
    signup_data = {"secret": str(b64encode(data).decode('UTF-8'))}
    signup_req = requests.post(url + "/signup", json=signup_data, headers={"Content-Type": "application/json"})
    if signup_req.status_code != 200:
        print("fail signup_req status_code != 200:", signup_req.status_code, signup_req.content)
        return
    ret = int_to_bytes(int.from_bytes(data, 'big', signed=False), 256)
    print("success signup user with uid",uid, "secret_data", secret_data, "encrypted_secret_data", get_number_trunc(data))
    return ret

def host_ret(uid):
    host_ret_data = {"uid":uid}
    host_ret_req = requests.post(url + "/host", json=host_ret_data, headers={"Content-Type": "application/json"})
    if host_ret_req.status_code != 200:
        print("fail host_ret_req status_code != 200:", host_ret_req.status_code, host_ret_req.content)
        return False
    print("success started retrieve with host_retrieve api for uid:",uid)
    return True

def user_ret(uid):
    key = get_random_bytes(32)
    cipher = ChaCha20_Poly1305.new(key=key)

    data = encrypt_rsa(b64encode(key)+b64encode(cipher.nonce), pk_file)
    user_ret_data = {"uid":uid, "secret":str(b64encode(data).decode('UTF-8'))}
    user_ret_req = requests.post(url + "/user", json=user_ret_data, headers={"Content-Type": "application/json"})
    if user_ret_req.status_code != 200:
        print("fail user_ret_req status_code != 200:", user_ret_req.status_code, user_ret_req.content)
        return

    return_data = b64decode(user_ret_req.content)
    ciphertext = bytes(return_data[:-16])
    tag = bytes(return_data[-16:])
    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8').rstrip(chr(0))
    print("success completed retrieve with user_retrieve api for uid:",uid)
    return plaintext

def check_retrieval(uid, expected, plaintext):
    uid_chr="".join([chr(x) for x in int_to_bytes(uid,4)])
    # print([ord(x) for x in plaintext[:4]])
    assert(str(plaintext) == str(uid_chr+expected))
    print("check_retrieval returned:", str(get_number_hex([ord(x) for x in plaintext])), str(get_number([ord(x) for x in plaintext[:4]]))+","+"".join(plaintext[4:]),"expected:",str(uid)+","+expected,str(get_number_hex([ord(x) for x in uid_chr+expected])))


def audit(users=None, retrievals=None):
    get_audit_req = requests.get(url + '/audit')
    if get_audit_req.status_code != 200:
        print("get_audit_req status_code != 200:", get_audit_req.status_code, get_audit_req.content)
        return
    audit_data = json.loads(get_audit_req.content)
    audit_tree = make_tree(audit_data["tree"]["nodes"])
    print("audit_data[tree]",print_tree(audit_tree))
    assert(audit_data["retrieve_count"] <= max_count)
    print("audit_data retrieve_count",audit_data["retrieve_count"], "MAX_retrieve", max_count)
    print()
    if users is not None:
        print("audit_data users_list", list(map(get_number_trunc,audit_data["users"])))
        for (uid,secret) in users:
            print("audit_data user uid:",uid,"encrypted secret data",get_number_trunc(secret))
            assert(secret in audit_data["users"])
    print()
    if retrievals is not None:
        print("audit_data retrievals", list(map(get_number_trunc,audit_data["retrieve"])))
        for (uid,secret) in retrievals:
            print("audit_data retrieved uid:",uid,"encrypted secret data", get_number_trunc(secret))
            assert(secret in audit_data["retrieve"])

get_pk()
uid_1 = 1
test_data_1 = "hello1"
uid_2 = 2
test_data_2 = "hello2"
uid_3 = 3
test_data_3 = "hello3"
secret_1 = signup(uid_1, test_data_1)
if secret_1 is None:
    exit(1)
secret_2 = signup(uid_2, test_data_2)
if secret_2 is None:
    exit(1)
secret_3 = signup(uid_3, test_data_3)
if secret_3 is None:
    exit(1)
print()

resp = host_ret(uid_1)
if not resp:
    exit(1)
time.sleep(5)
response_1 = user_ret(uid_1)
if response_1 is None:
    exit(1)
check_retrieval(uid_1, test_data_1, response_1)
print()


resp = host_ret(uid_3)
if not resp:
    exit(1)
time.sleep(5)
response_3 = user_ret(uid_3)
if response_3 is None:
    exit(1)
check_retrieval(uid_3, test_data_3, response_3)
print()

resp = host_ret(uid_2)
if not resp:
    exit(1)
time.sleep(5)
response_2 = user_ret(uid_2)
if response_2 is not None: #MAX_retrieve = 2
    exit(1)
print("\n")

audit(users=[(uid_1,secret_1), (uid_2,secret_2), (uid_3,secret_3)], retrievals=[(uid_1,secret_1), (uid_3,secret_3)])

print("\nsuccess")
