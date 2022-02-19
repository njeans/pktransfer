import requests
import json
from base64 import b64encode, b64decode
import Crypto
from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC

import time
import math
import sys
from datetime import datetime
import pprint

from web3.providers.eth_tester import EthereumTesterProvider
from web3 import Web3
from solcx import compile_source


url = "http://localhost:8000"
pk_file = "enclave_public_key.pem"
uid_size = 4
max_count = 2

class bcolors:
    USER1 = '\033[95m'
    USER2 = '\033[94m'
    USER3 = '\033[96m'
    USER4 = '\033[92m'
    USER5 = '\033[93m'
    AUDIT = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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

def get_number_hex(values,reverse_values=True):
    total = 0
    final_values = values
    if reverse_values:
        final_values = reversed(values)
    for val in final_values:
        total = (total << 8) + val
    return hex(total)

def get_number(values):
    total = 0
    for val in values:
        total = (total << 8) + val
    return total

def get_number_trunc(values,reverse_values=True):
    h=get_number_hex(values,reverse_values=reverse_values)
    return str(h[:10])+"..."


class Tree(object):
    def __init__(self):
        self.left = None
        self.right = None
        self.data = None
        self.leaf = None

    def __str__(self):
        return str(self.data)

def helper(nodes,pos,curr,leaves):
    level = math.floor(math.log(pos,2))
    left_pos = 2**(level+1) + (pos-2**level) * 2
    right_pos = 2**(level+1) + (pos-2**level) * 2 + 1
    if pos > len(nodes) - len(leaves):
        curr.leaf = leaves[pos-(len(nodes)-len(leaves))-1]

    if left_pos <= len(nodes):
        curr.left = Tree()
        curr.left.data = nodes[left_pos-1]
        helper(nodes,left_pos,curr.left,leaves)
    if right_pos <= len(nodes):
        curr.right =  Tree()
        curr.right.data = nodes[right_pos-1]
        helper(nodes,right_pos,curr.right,leaves)


def make_tree(nodes,leaves):
    root = Tree()
    pos = 1
    root.data = nodes[0]
    helper(nodes,pos,root,leaves)
    return root

def print_tree(node, level=0, right=False, p=lambda x: get_number_trunc(x)):
    if node != None:
        print_tree(node.left, level + 1,p=p)
        leaf=""
        if node.leaf is not None:
            leaf = " leaf: [" + str(node.leaf) + "]"
        if right:
            print(bcolors.AUDIT+"\t\t\t" * level + '-> (' + p(node.data)+")"+leaf,bcolors.ENDC)
            # print("\t" * level + '\\', node.data)
        else:
            # print("\t" * level + '/', node.data)
            print(bcolors.AUDIT+"\t\t\t" * level + '-> (' + p(node.data)+")"+leaf,bcolors.ENDC)
        print_tree(node.right, level + 1, True,p=p)

def helper_index(curr_path,leaf_index):
    if leaf_index <= 0:
        return curr_path
    if leaf_index % 2 == 1:
        leaf_level =  math.floor(math.log(leaf_index+1,2))
        parent_index = (leaf_index + 1 - 2**(leaf_level+1))/2 -1 + 2**leaf_level
        curr_path.append(leaf_index+1)
        curr_path.append(int(parent_index))
        helper_index(curr_path,int(parent_index))
    else:
        leaf_level =  math.floor(math.log(leaf_index+1,2))
        parent_index = (leaf_index + 1 - 2**(leaf_level+1) - 1)/2 - 1 + 2**leaf_level
        curr_path.append(leaf_index-1)
        curr_path.append(int(parent_index))
        helper_index(curr_path,int(parent_index))

def get_path(nodes,leaf_index):
    path=[leaf_index]
    node_path_pairs = []
    for i in range(0,len(path)-2,2):
        n1 = path[i]
        n2 = path[i+1]
        if n2 >= len(nodes): #duplicate leaf node if there are odd number of leaf nodes
            n2 = n1
        if n1 > n2:
            node_path_pairs.append((nodes[n2],nodes[n1],nodes[path[i+2]]))
        else:
            node_path_pairs.append((nodes[n1],nodes[n2],nodes[path[i+2]]))
    return node_path_pairs

def check_path(path,leaf,color,entry):
    entry_data = int_to_bytes(entry["uid"],4)+int_to_bytes(entry["countdown"],8)+int_to_bytes(entry["retrieve_count"],8)
    h_entry = Crypto.Hash.SHA256.new(bytearray(entry_data))
    print(color+"hash of entry",str(entry),"->",get_number_trunc(leaf),bcolors.ENDC)
    # print(get_number_hex(leaf,reverse_values=False)==("0x"+h_entry.hexdigest().lstrip("0")),("0x"+h_entry.hexdigest().lstrip("0"))[:10],get_number_trunc(leaf,reverse_values=False))
    assert(get_number_hex(leaf,reverse_values=False)==("0x"+h_entry.hexdigest().lstrip("0")))
    for node_path_pairs in path:
        left,right,res=node_path_pairs
        h = Crypto.Hash.SHA256.new(bytearray(left+right))
        print(color+"combine",get_number_trunc(left),"+",get_number_trunc(right),"->",get_number_trunc(res),bcolors.ENDC)
        # print("0x"+h.hexdigest().lstrip("0")==get_number_hex(res,reverse_values=False),("0x"+h.hexdigest().lstrip("0"))[:10],get_number_trunc(res,reverse_values=False))
        assert("0x"+h.hexdigest().lstrip("0")==get_number_hex(res,reverse_values=False))

def compile_source_file(file_path):
    with open(file_path, 'r') as f:
        source = f.read()
    return compile_source(source,output_values=['abi', 'bin'])

def setupW3():
    provider = Web3.HTTPProvider('http://172.17.0.4:8545', request_kwargs={'timeout': 60})
    w3 = Web3(provider)
    admin = w3.eth.accounts[0]
    contract_source_path = '/root/sgx/samplecode/pktransfer/solidity/PKtransfercancel.sol'
    compiled_sol = compile_source_file(contract_source_path)
    contract_id, contract_interface = compiled_sol.popitem()
    contract_addresss = deploy_contract(w3, contract_interface,admin)
    contract = w3.eth.contract(address=contract_addresss, abi=contract_interface["abi"])
    return w3,contract,admin

def deploy_contract(w3, contract_interface,admin_addr):
    tx_hash = w3.eth.contract(
    abi=contract_interface['abi'],
    bytecode=contract_interface['bin']).constructor().transact({"from":admin_addr})
    address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
    return address

def send_tx(foo,user_addr):
    gas_estimate = foo.estimateGas()
    # print(f'\tGas estimate to transact: {gas_estimate}')

    if gas_estimate < 100000:
         # print("\tSending transaction")
         tx_hash = foo.transact({"from":user_addr})
         receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
         # print("\tTransaction receipt mined:")
         # pprint.pprint(dict(receipt))
         print("\tWas transaction successful?"+str(receipt["status"]))
    else:
         print("Error! Gas cost exceeds 100000")

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

def signup(uid, secret_data, cancel_public_key, w3addr):
    message = uid.to_bytes(4, 'big')+(secret_data).encode('utf8')
    data = encrypt_rsa(message, pk_file)
    signup_data = {
        "secret": str(b64encode(data).decode('UTF-8')),
        "cancel_key": {
            "x": str(b64encode(int(cancel_public_key.pointQ.x).to_bytes(32, 'big')).decode('UTF-8')),
            "y": str(b64encode(int(cancel_public_key.pointQ.y).to_bytes(32, 'big')).decode('UTF-8'))
            }
        }
    print("signup_data",signup_data)
    signup_req = requests.post(url + "/signup", json=signup_data, headers={"Content-Type": "application/json"})
    if signup_req.status_code != 200:
        print("fail signup_req status_code != 200:", signup_req.status_code, signup_req.content)
        return
    ret = int_to_bytes(int.from_bytes(data, 'big', signed=False), 256)
    public_key =  str(hex(int(cancel_public_key.pointQ.x)))+str(hex(int(cancel_public_key.pointQ.y)))
    send_tx(contract.functions.new_user(bytearray(public_key,'utf-8')),w3addr)
    print("Billboard updated for "+str(uid)+":",contract.functions.get_user().call({"from":w3addr}))
    return ret

def host_ret(uid):
    host_ret_data = {"uid":uid}
    host_ret_req = requests.post(url + "/host", json=host_ret_data, headers={"Content-Type": "application/json"})
    if host_ret_req.status_code != 200:
        print("fail host_ret_req status_code != 200:", host_ret_req.status_code, host_ret_req.content)
        return False
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

    return plaintext

def check_retrieval(uid, expected, plaintext,color):
    uid_chr="".join([chr(x) for x in int_to_bytes(uid,4)])
    assert(str(plaintext) == str(uid_chr+expected))
    print(color+"check_retrieval returned:", str(get_number_hex([ord(x) for x in plaintext])), str(get_number([ord(x) for x in plaintext[:4]]))+","+"".join(plaintext[4:]),"expected:",str(uid)+","+expected,str(get_number_hex([ord(x) for x in uid_chr+expected])),bcolors.ENDC)

def cancel_ret(uid,cancel_message,signature,message_hash,user_addr):
    send_tx(contract.functions.cancel_message(message, message_hash, signature, int(round(datetime.now().timestamp()))), user_addr)
    print("Billboard updated for "+str(uid)+":",contract.functions.get_user().call({"from":user_addr}))
    cancel_ret_data = {
        "uid":uid,
        "data":str(b64encode(cancel_message).decode('UTF-8')),
        "signature":{
            "x": str(b64encode(signature[:32]).decode('UTF-8')),
            "y": str(b64encode(signature[32:]).decode('UTF-8'))
            }
    }
    cancel_ret_req = requests.post(url + "/cancel", json=cancel_ret_data, headers={"Content-Type": "application/json"})
    if cancel_ret_req.status_code != 200:
        print("fail cancel_ret_req status_code != 200:", cancel_ret_req.status_code, cancel_ret_req.content)
        return False
    return True

def audit_tree():
    get_audit_req = requests.get(url + '/audit')
    if get_audit_req.status_code != 200:
        print("get_audit_req status_code != 200:", get_audit_req.status_code, get_audit_req.content)
        return
    audit_data = json.loads(get_audit_req.content)
    # print(json.dumps(audit_data["tree"],indent=2))

    leaves = audit_data["tree"]["leaves"]
    nodes = audit_data["tree"]["nodes"]
    audit_tree = make_tree(nodes,leaves)
    print(bcolors.AUDIT+"audit_data[tree]",bcolors.ENDC)
    print_tree(audit_tree)
    assert(audit_data["retrieve_count"] <= max_count)
    print(bcolors.AUDIT+"audit_data retrieve_count",audit_data["retrieve_count"], "MAX_retrieve", max_count,bcolors.ENDC)
    print()
    return nodes,leaves

def audit_user(uid,secret,tree_nodes,leaves,color):
    print
    leaf_index = 0
    for i in range(len(leaves)):
        if leaves[i]["uid"] == uid:
            leaf_index=len(tree_nodes)-len(leaves)+i
            path = get_path(tree_nodes,leaf_index)
            check_path(path,tree_nodes[leaf_index],color,leaves[i])
            print()


def tmp():
    cancel_key = ECC.generate(curve='P-256')
    uid = 2
    test_data="hello 223"
    secret = signup(uid, test_data, cancel_key.public_key())
    cancel_message = SHA256.new( uid.to_bytes(4, 'big'))
    signer = DSS.new(cancel_key, 'fips-186-3')
    signature = signer.sign(cancel_message)
    resp = host_ret(uid)
    resp = cancel_ret(uid,cancel_message.digest(),signature)
    exit(0)


# get_pk()
# tmp()
w3,contract,admin_addr = setupW3()
users_list = [
                [1,"hello1",ECC.generate(curve='P-256'),bcolors.USER1,w3.eth.accounts[1]],
                [2,"hello2",ECC.generate(curve='P-256'),bcolors.USER2,w3.eth.accounts[2]],
                [3,"hello3",ECC.generate(curve='P-256'),bcolors.USER3,w3.eth.accounts[3]],
                [4,"hello4",ECC.generate(curve='P-256'),bcolors.USER4,w3.eth.accounts[4]],
                [5,"bye5",ECC.generate(curve='P-256'),bcolors.USER5,w3.eth.accounts[5]]
            ]

user_secret = [0,0,0,0,0]

only_audit = False
if len(sys.argv) > 1 and sys.argv[1] == "audit":
    only_audit = True #only run the auditing scheme

if not only_audit:
    for i in [4]:#range([4]):#[len(users_list)):
        uid,test_data,cancel_key,color,w3addr = users_list[i]
        secret = signup(uid, test_data, cancel_key.public_key(), w3addr)
        if secret is None:
            exit(1)
        print(color+"success signup user with uid",uid, "secret_data", test_data, "encrypted_secret_data", get_number_trunc(secret),bcolors.ENDC)
        user_secret[i]=secret
    print()

    for i in [0,2,3,4]:
        uid,test_data,cancel_key,color,w3addr = users_list[i]
        secret = user_secret[i]
        resp = host_ret(uid)
        if not resp:
            exit(1)
        print(color+"success started retrieve with host_retrieve api for uid:",uid,bcolors.ENDC)

    for i in [4]:
        uid,test_data,cancel_key,color,w3addr = users_list[i]
        message = b'\x19Ethereum Signed Message:\n'+uid.to_bytes(4, 'big')
        message_hash = SHA256.new(message)
        signer = DSS.new(cancel_key, 'fips-186-3')
        signature = signer.sign(message_hash)
        # resp = host_ret(uid)
        resp = cancel_ret(uid,message,signature,message_hash.hexdigest(),w3addr)
        if not resp:
            exit(1)
        print(color+"success started cancel retrieve for uid:",uid,bcolors.ENDC)

    for i in [3,4]:
        uid,test_data,cancel_key,color,w3addr = users_list[i]
        response = user_ret(uid)
        if response is None:
            print(color+"success completed retrieve with user_retrieve api for uid:",uid,bcolors.ENDC)
        else:
            print(color+"FAIL completed retrieve with user_retrieve api for uid:",uid,bcolors.ENDC)
        print()

print("\n"+bcolors.AUDIT+"Public Audit Website------------------------------------------------------------------------------------------------------",bcolors.ENDC)


tree_nodes,leaves = audit_tree()
print(list(map(get_number_trunc,tree_nodes)))

for i in range(len(users_list)):
    uid,test_data,cancel_key,color,w3addr = users_list[i]
    print(color+"Begin user",uid,"Auditing------------------------------------------------------------------------------------------------------",bcolors.ENDC)
    audit_user(uid,None,tree_nodes,leaves,color)
