# curr=/home/rokwall/code/pktransfer
curr=$PWD
echo $curr
docker run --rm \
  -v $curr/pktransfer:/root/sgx/samplecode/pktransfer \
  --device /dev/isgx \
  -ti pktransferenclave
# exit 0
# export SGX_SDK_RUST=~/sgx/incubator-teaclave-sgx-sdk-master/
# LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/ /opt/intel/sgx-aesm-service/aesm/aesm_service &
# make
# cd bin
# ./app > ../server.log &
# cd ..
# python3 test.py
