curr=$PWD
# echo $curr

GANACHEIP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pktransferganache)
echo "GANACHEIP=$GANACHEIP"
# docker run --rm -v $PWD/pktransfer/:/root/sgx/samplecode/pktransfer/ --env GANACHEIP="$GANACHEIP"  -ti pktransferenclave
docker run --rm --env GANACHEIP="$GANACHEIP" -ti pktransferenclave /bin/bash
