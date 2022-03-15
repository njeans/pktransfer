# docker run -v /Users/nerla/code/rust/pktransfer/pktransfer/solidity/:/sources ethereum/solc:stable -o /sources/output --base-path  /sources --include-path /sources/openzeppelin-contracts --overwrite --abi --bin /sources/PKtransfercancel.sol

docker run -v /Users/nerla/code/rust/pktransfer/pktransfer/solidity/:/sources/ ethereum/solc:0.6.12 -o /sources/output --base-path  /sources --overwrite --abi --bin /sources/tmp2.sol
