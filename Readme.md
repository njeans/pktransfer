# secret data transfer enclave

## Demo
* build Dockerfile `build.sh`
* run Docker `run.sh`
* run Docker in simulation `run_sim.sh`

* run full demo
```
make
cd bin
./app > ../server.log &
cd ..
python3 test.py
```
* run only auditing portion of demo
```
make
cd bin
./app > ../server.log &
cd ..
python3 test.py audit
```

* reset demo by deleting `bin/data.sealed`

## pktransfer code
### pktransfer/app/src/main.rs
Contains rest server that sends parses requests and calls enclave functions

### pktransfer/enclave
Contains enclave code

#### src/crypto.rs
public key/private key cryptography function implementations

#### src/data.rs
functions related to database (add entry, create, update)

#### src/time.rs
function related to update of the timestamp

#### src/merkletree.rs
function related to merkle tree
