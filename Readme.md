# secret data transfer enclave

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
function related to update of the timestamp

#### src/merkletree.rs
function related to merkle tree

## solidity code
### pktransfer/solidity/PKtransfercancel.sol
solidity contract
