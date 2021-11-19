
echo "build_run.sh"

# make clean
make
cd bin
./app > server.log &
cd ..
cat server.log
