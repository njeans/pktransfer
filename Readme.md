# Secret data transfer enclave

## Overview
This project and demo is an implementation of a secret data transfer application using Intel SGX secure enclaves and blockchain based bulletin board. This application tries to solve the problem of secure data recovery by designating a semi-trusted administrator that can verify the user's identity during the recovery process. It employs different strategies to ensure accountability of the administrator.  In order to limit the admin's power we implement restrictions on the number and frequency of data retrieval, have a mechanism for users to be notified of and cancel a fraudulent retrieval, and allow for public auditing of all signups and retrievals in the enclave.

## Demo output
![Output of Demo](docs/demo1.png?raw=true)
* Signup 4 users
* Users 2,3,4 start retreival process
* User 3 cancels retreival process
* User 3 fails to complete retreival (because it was canceled)
* User 4 completes retreival and checks that the correct data was recovered

![Output of Demo](docs/demo2.png?raw=true)
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
