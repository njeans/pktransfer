
echo "build_run.sh"

# make clean
make
cd bin
rm data.sealed
./app > server.log &
cd ..
cat server.log
