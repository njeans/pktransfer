FROM initc3/teaclave-sgx-sdk:e8a9fc22

RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get update && apt-get install -y \
                python3-dev \
                python3-pip \
                libssl-dev \
                solc \
        && rm -rf /var/lib/apt/lists/*

RUN pip3 install requests pycryptodome cython py-solc-x web3 ipython

ENV SGX_MODE=SW
ENV SGX_SDK_RUST=/root/sgx/incubator-teaclave-sgx-sdk-master

RUN git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git \
            /root/sgx/incubator-teaclave-sgx-sdk-master \
        && cd /root/sgx/incubator-teaclave-sgx-sdk-master 

WORKDIR /root/sgx/samplecode/pktransfer

COPY pktransfer .

RUN /bin/bash -c "source /opt/sgxsdk/environment; \
                  source /root/.cargo/env; \
                  make clean && make;"
