curr=$PWD
# echo $curr
#docker run --rm -v $PWD/pktransfer:/root/sgx/samplecode/pktransfer --env GANACHEIP="$GANACHEIP"  -ti pktransferenclave
docker run --rm --env GANACHEIP="$GANACHEIP" -ti pktransferenclave

# Run ganache server
# docker run --name pktransferganache -it --publish 8545:8545 trufflesuite/ganache-cli:latest --accounts 10 --debug

# Builds PKtransfercancel.sol source
# docker run -v /Users/nerla/code/rust/pktransfer/pktransfer/solidity/:/sources ethereum/solc:stable -o /sources/output --abi --bin /sources/PKtransfercancel.sol
