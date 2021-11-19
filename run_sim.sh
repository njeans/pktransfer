curr=$PWD
echo $curr
docker run -v $curr/pktransfer:/root/sgx/samplecode/pktransfer  -ti pktransferenclave
