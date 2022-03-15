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
import os

from web3.providers.eth_tester import EthereumTesterProvider
from web3 import Web3
import solcx
from solcx import compile_source
from eth_account.messages import encode_defunct
import eth_account

GANACHEIP = os.getenv('GANACHEIP', '172.17.0.4')
enclave_url = "http://localhost:8000"
pk_file = "enclave_public_key.pem"
uid_size = 4
max_count = 2

class bcolors:
    USER1 = '\033[95m'
    USER2 = '\033[93m'
    USER3 = '\033[96m'
    USER4 = '\033[92m'
    USER5 = '\033[94m'
    AUDIT = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def encrypt_rsa(msg_plaintext, pem_filename):
    key = RSA.importKey(open(pem_filename).read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)
    secret = cipher.encrypt(msg_plaintext)
    return secret

def decrypt_rsa(msg_plaintext, pem_filename):
    key = RSA.importKey(open(pem_filename).read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=Crypto.Hash.SHA256)
    secret = cipher.encrypt(msg_plaintext)
    data = int_to_bytes(int.from_bytes(secret, 'big', signed=False), 256)
    return data

def int_to_bytes(val, num_bytes):
    return [(val & (0xff << pos*8)) >> pos*8 for pos in reversed(range(num_bytes))]

def bytes_to_hex_trunc(x):
    return "0x"+str(x.hex()[:10])+"..."

def int_to_hex_trunc(x):
    return "0x"+str(hex(x)[:10])+"..."

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
    base="/root/sgx/samplecode/pktransfer/solidity"
    with open(file_path, 'r') as f:
        source = f.read()
    return compile_source(source,
        output_values=['abi', 'bin'],
        base_path=base,
        allow_paths=[base+"/openzeppelin-contracts"])

def setupW3(audit):
    provider = Web3.HTTPProvider(f'http://{GANACHEIP}:8545', request_kwargs={'timeout': 60})
    w3 = Web3(provider)
    admin = w3.eth.accounts[0]
    with open("/root/sgx/samplecode/pktransfer/accounts_info.json") as f:
        accounts_info = json.loads(f.read())
    contract_source_path = '/root/sgx/samplecode/pktransfer/solidity/PKtransfercancel.sol'
    compiled_sol = compile_source_file(contract_source_path)
    abis = []
    bins = ""
    contract_id=""
    for x in compiled_sol:
        contract_id+=x
        contract_interface=compiled_sol[x]
        abis=abis+contract_interface['abi']
        bins=bins+contract_interface['bin']

    if not audit:
        contract_addresss,contract,_ = deploy_contract(w3, abis, bins,admin)
        with open("contract_address.txt","w") as f:
            f.write(contract_addresss)
    else:
        with open("contract_address.txt") as f:
            contract_addresss=f.read()
        _,contract,_ = deploy_contract(w3, abis, bins,admin, contract_address=contract_addresss)
    print(f'Deployed {contract_id} to: {contract_addresss}')
    return w3,contract,admin,accounts_info

def deploy_contract(w3, abis,bins,admin_addr,contract_address=None):
    contract = w3.eth.contract(address=contract_address,abi=abis, bytecode=bins)
    tx_hash = contract.constructor().transact({"from":admin_addr})
    address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
    contract = w3.eth.contract(address=address, abi=abis)
    return address,contract,tx_hash

def send_tx(foo,user_addr):
    gas_estimate = foo.estimateGas()
    # print(f'\tGas estimate to transact: {gas_estimate}')

    if gas_estimate < 1000000:
         # print("\tSending transaction")
         tx_hash = foo.transact({"from":user_addr})
         receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
         # print("\tTransaction receipt mined:")
         # pprint.pprint(dict(receipt))
         # print("\tWas transaction successful?"+str(receipt["status"]))
    else:
         print("Error! Gas cost exceeds 1000000:",gas_estimate)

def get_pk():
    get_pub_key_req = requests.get(enclave_url + '/public_key')
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
    print("success download enclave public key into",pk_file)

def signup(uid, secret_data, cancel_public_key, w3addr, color):
    message = uid.to_bytes(4, 'big')+secret_data.encode('utf8')
    data = encrypt_rsa(message, pk_file)
    signup_data = {
        "secret": str(b64encode(data).decode('UTF-8')),
        "cancel_key": str(b64encode(cancel_public_key).decode('UTF-8'))
        }

    signup_req = requests.post(enclave_url + "/signup", json=signup_data, headers={"Content-Type": "application/json"})
    if signup_req.status_code != 200:
        print("fail signup_req status_code != 200:", signup_req.status_code, signup_req.content)
        return
    ret = int_to_bytes(int.from_bytes(data, 'big', signed=False), 256)
    send_tx(contract.functions.new_user(cancel_public_key),w3addr)
    user_info=contract.functions.get_user().call({"from":w3addr})
    print(color+"Billboard updated for "+str(uid)+":",
            "cancel_public_key",bytes_to_hex_trunc(user_info[0]),
            "cancel_message","\""+user_info[1]+"\"",
            "canceled?",user_info[2],
            "timestamp",user_info[3],bcolors.ENDC)
    return ret

def host_ret(uid):
    host_ret_data = {"uid":uid}
    host_ret_req = requests.post(enclave_url + "/host", json=host_ret_data, headers={"Content-Type": "application/json"})
    if host_ret_req.status_code != 200:
        print("fail host_ret_req status_code != 200:", host_ret_req.status_code, host_ret_req.content)
        return False
    return True

def user_ret(uid):
    key = get_random_bytes(32)
    cipher = ChaCha20_Poly1305.new(key=key)

    data = encrypt_rsa(b64encode(key)+b64encode(cipher.nonce), pk_file)
    user_ret_data = {"uid":uid, "secret":str(b64encode(data).decode('UTF-8'))}

    user_ret_req = requests.post(enclave_url + "/user", json=user_ret_data, headers={"Content-Type": "application/json"})
    if user_ret_req.status_code != 200:
        print("fail user_retreive_request status_code != 200:", user_ret_req.status_code, user_ret_req.content)
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

def cancel_ret(uid,cancel_message,signature,message_hash,ec_recover_args, user_addr,color):
    send_tx(contract.functions.cancel_message(cancel_message, ec_recover_args["hash"], ec_recover_args["v"], ec_recover_args["r"], ec_recover_args["s"] ,int(round(datetime.now().timestamp()))), user_addr)
    user_info=contract.functions.get_user().call({"from":w3addr})
    if user_info[2]: #verification successful
        print(color+"successful verification of signature",bcolors.ENDC)
        print(color+"Billboard updated for "+str(uid)+":",
                "cancel_public_key",bytes_to_hex_trunc(user_info[0]),
                "cancel_message","\""+user_info[1]+"\"",
                "canceled?",user_info[2],
                "timestamp",user_info[3],bcolors.ENDC)
    else:
        print(color+"fail verification of signiture Billboard not updated",bcolors.ENDC)
        return

    x=int.from_bytes(signature[:32], "big").to_bytes(32, byteorder='little')
    y=int.from_bytes(signature[32:64], "big").to_bytes(32, byteorder='little')
    cancel_ret_data = {
        "uid":uid,
        "data":str(b64encode(message_hash).decode('UTF-8')),
        "signature":str(b64encode(signature).decode('UTF-8')),
    }
    cancel_ret_req = requests.post(enclave_url + "/cancel", json=cancel_ret_data, headers={"Content-Type": "application/json"})

    if cancel_ret_req.status_code != 200:
        print("fail cancel_ret_req status_code != 200:", cancel_ret_req.status_code, cancel_ret_req.content)
        return False

    return True

def audit_tree():
    get_audit_req = requests.get(enclave_url + '/audit')
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

def to_32byte_hex(val):
    return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))

def load_eth_key(i):
    user_addr=w3.eth.accounts[i]
    private_key=get_number_hex(eth_accounts["addresses"][user_addr.lower()]["secretKey"]["data"],reverse_values=False)
    pub_key=eth_accounts["addresses"][user_addr.lower()]["publicKey"]["data"]
    return {"private_key":private_key,"public_key":bytearray([0x04] + pub_key)}

def ecdsa_sign(message,private_key):
    msghash = encode_defunct(text=message)
    signed_message=eth_account.Account.sign_message(msghash, private_key)
    message_hash=Web3.toBytes(signed_message.messageHash).rjust(32, b'\0')
    signature = Web3.toBytes(signed_message.signature[:64]).rjust(32, b'\0')
    ec_recover_args = {
        "hash":to_32byte_hex(signed_message.messageHash),
        "v":signed_message.v,
        "r":to_32byte_hex(signed_message.r),
        "s":to_32byte_hex(signed_message.s),
    }
    return message_hash,signature,ec_recover_args

def run_demo():
    get_pk()

    global w3, contract, admin_addr,eth_accounts, w3addr
    w3,contract,admin_addr,eth_accounts = setupW3(only_audit)

    users_list = [
        [1,"hello1",load_eth_key(1),bcolors.USER1,w3.eth.accounts[1]],
        [2,"hello2",load_eth_key(2),bcolors.USER2,w3.eth.accounts[2]],
        [3,"hello3",load_eth_key(3),bcolors.USER3,w3.eth.accounts[3]],
        [4,"hello4",load_eth_key(4),bcolors.USER4,w3.eth.accounts[4]]
    ]
    # tmp()

    user_secret = [0,0,0,0,0]
    signup_list =list(range(len(users_list)))
    start_ret_list = [1,2,3]
    cancel_ret_list = [2]
    finish_ret_list = [2,3]

    if not only_audit:
        print()
        print("Signup users:",[users_list[x][0] for x in signup_list])
        for i in signup_list:
            uid,test_data,cancel_key,color,w3addr = users_list[i]
            secret = signup(uid, test_data, cancel_key["public_key"], w3addr,color)
            if secret is None:
                exit(1)
            print(color+"success signup user with uid",uid, "secret_data", test_data, "encrypted_secret_data", get_number_trunc(secret),bcolors.ENDC)
            user_secret[i]=secret
        print()

        print("Start retreive users:",[users_list[x][0] for x in start_ret_list])
        for i in start_ret_list:
            uid,test_data,cancel_key,color,w3addr = users_list[i]
            secret = user_secret[i]
            resp = host_ret(uid)
            if not resp:
                exit(1)
            print(color+"success started retrieve with host_retrieve api for uid:",uid,bcolors.ENDC)
        print()

        print("Cancel retreive users:",[users_list[x][0] for x in cancel_ret_list])
        for i in cancel_ret_list:
            uid,test_data,cancel_key,color,w3addr = users_list[i]
            message = 'Cancel retreieve '+str(uid)
            message_hash,signature,ec_recover_args=ecdsa_sign(message, cancel_key["private_key"])
            resp = cancel_ret(uid,message,signature,message_hash,ec_recover_args,w3addr,color)
            if not resp:
                print(color+"fail cancel retrieve for uid:",uid,bcolors.ENDC)
            else:
                print(color+"success cancel retrieve for uid:",uid,bcolors.ENDC)
        print()

        print("Finish retreive users:",[users_list[x][0] for x in finish_ret_list])
        for i in finish_ret_list:
            uid,test_data,cancel_key,color,w3addr = users_list[i]
            response = user_ret(uid)
            if response is None:
                print(color+"FAIL completed retrieve with user_retrieve api for uid:",uid,bcolors.ENDC)
            else:
                print(color+"success completed retrieve with user_retrieve api for uid:",uid,"retreived:",response,bcolors.ENDC)
        print()

        print("Summary:")
        for i in list(range(len(users_list))):
            uid = users_list[i][0]
            color = users_list[i][3]
            if i in signup_list and i in start_ret_list and i in cancel_ret_list and i in finish_ret_list:
               print(color,"\tuid:",uid,"Signed up, Started retrieve, Cancel retreive, Fail retreive",bcolors.ENDC)
            elif i in signup_list and i in start_ret_list and i in finish_ret_list:
               print(color,"\tuid:",uid,"Signed up, Started retrieve, Completed Retreive",bcolors.ENDC)
            elif i in signup_list and i in start_ret_list:
               print(color,"\tuid:",uid,"Signed up, Started retrieve",bcolors.ENDC)
            elif i in signup_list:
               print(color,"\tuid:",uid,"Signed up",bcolors.ENDC)

    print("\n"+bcolors.AUDIT+"Public Audit Billboard------------------------------------------------------------------------------------------------------",bcolors.ENDC)
    for i in range(len(users_list)):
        uid,test_data,cancel_key,color,w3addr = users_list[i]
        user_info=contract.functions.get_user().call({"from":w3addr})
        print(color+"Billboard status for "+str(uid)+":",
                "cancel_public_key:",bytes_to_hex_trunc(user_info[0]),
                "cancel_message:","\""+user_info[1]+"\"",
                "canceled?:",user_info[2],
                "timestamp:",user_info[3],bcolors.ENDC)

    print("\n"+bcolors.AUDIT+"Public Audit Website------------------------------------------------------------------------------------------------------",bcolors.ENDC)


    tree_nodes,leaves = audit_tree()


    for i in range(len(users_list)):
        uid,test_data,cancel_key,color,w3addr = users_list[i]
        print(color+"Begin user",uid,"Auditing------------------------------------------------------------------------------------------------------",bcolors.ENDC)
        audit_user(uid,None,tree_nodes,leaves,color)


only_audit = False
if len(sys.argv) > 1 and sys.argv[1] == "audit":
    only_audit = True #only run the auditing scheme

run_demo()
