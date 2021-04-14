FROM baiduxlab/sgx-rust

ENV SGX_SDK_RUST=~/sgx/incubator-teaclave-sgx-sdk-master/

RUN git clone --depth 1 -b v1.0.9 https://github.com/apache/incubator-teaclave-sgx-sdk /root/sgx
COPY . /root/sgx/samplecode/pktransfer
WORKDIR /root/sgx/samplecode/pktransfer
