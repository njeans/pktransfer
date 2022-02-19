FROM baiduxlab/sgx-rust:1804-1.1.3
#
RUN curl -sS https://bootstrap.pypa.io/get-pip.py >> setup.py && python3 setup.py
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get update -y && apt-get -y install python3-dev libssl-dev solc
RUN pip3 install requests pycryptodome cython py-solc-x web3

RUN export SGX_MODE=SW
RUN export SGX_SDK_RUST=/root/sgx/incubator-teaclave-sgx-sdk-master
WORKDIR /root/sgx/
RUN git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git incubator-teaclave-sgx-sdk-master
COPY ./pktransfer /root/sgx/samplecode/pktransfer
# COPY ./incubator-teaclave-sgx-sdk-master /root/sgx/incubator-teaclave-sgx-sdk-master
WORKDIR /root/sgx/samplecode/pktransfer
# RUN cargo
# RUN make clean && make