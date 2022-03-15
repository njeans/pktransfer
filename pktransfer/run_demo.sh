cd bin
rm data.sealed
ls
./app > server.log &
APP_PID=$!
cd ..
sleep 2
python3 demo.py
#cat bin/server.log
kill $APP_PID
