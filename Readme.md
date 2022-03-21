# Secret data transfer enclave

## Overview
This project and demo is an implementation of a secret data transfer application using Intel SGX secure enclaves. This application consists of three parties: a user, an admin, and auditors. During signup the user backs up their secret data to the enclave without revealing it to the admin. There is a two step retreival process. First, the user uses some external mechanism to prove their identity to the admin. After a mandatory weight period they are able to finish the recovery of their data again without revealing it to the admin. In order to limit the admin's power we allow for caps on the number of users who can recover their data in a time period, have a mechanism for users to cancel retreival during the mandatory weight period, and allow for public auditing of all signups and retreivals in the enclave.

## Demo output
![Output of Demo](/pktransfer/blob/main/docs/demo1.png?raw=true)
* Signup 4 users
* Users 2,3,4 start retreival process
* User 3 cancels retreival process
* User 3 fails to complete retreival (because it was canceled)
* User 4 completes retreival and checks that the correct data was recovered

![Output of Demo](/pktransfer/blob/main/docs/demo2.png?raw=true)
* All users audit and verify the path for their merkle tree leaf node

## Demo Steps
* build Dockerfile `build.sh`
* run bulletin board `./run_ganache.sh`
* run Docker in simulation mode `run_sim.sh`
* run full demo
```
./run_demo.sh
```
or
```
make
cd bin
./app > ../server.log &
cd ..
python3 demo.py
```
* run only auditing portion of demo
```
make
cd bin
./app > ../server.log &
cd ..
python3 demo.py audit
```




* reset demo by deleting `bin/data.sealed` and restarting bulleting board

## pktransfer enclave code
### pktransfer/app/src/main.rs
Contains rest server that sends parses requests and calls enclave functions

### pktransfer/enclave
Contains enclave code

#### src/crypto.rs
public key/private key cryptography function implementations

#### src/data.rs
functions related to database (add entry, create, update) and data structures

#### src/time.rs
functions related to update of the timestamp

#### src/merkletree.rs
functions related to merkle tree

## solidity code
### pktransfer/solidity/PKtransfercancel.sol
solidity contract for implementation of bulletin board
