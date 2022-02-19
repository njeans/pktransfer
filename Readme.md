# secret data transfer enclave

## Demo Steps
* build Dockerfile `build.sh`
* run bulletin board `docker run --name pktransferganache -it --publish 8545:8545 trufflesuite/ganache-cli:latest --accounts 10 --debug`
* set `GANACHEIP` environment variable with:
```
docker inspect ganache | grep IPAddress
```
* run Docker in simulation mode `run_sim.sh`
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

* reset demo by deleting `bin/data.sealed` and restarting bulleting board

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
