./cmcumgr  -vvv --retries=5 --conntype=serial --connstring="dev=/dev/ttyUSB0,baud=115200" image upload zephyr.signed.bin
./cmcumgr --conntype=serial --connstring="dev=/dev/ttyUSB0,baud=115200" image list
./cmcumgr --conntype=serial --connstring="dev=/dev/ttyUSB0,baud=115200" image test 
./cmcumgr  -t 60 --conntype=serial --connstring="dev=/dev/ttyUSB0,baud=115200" reset
./cmcumgr --conntype=serial --connstring="dev=/dev/ttyUSB0,baud=115200" image confirm
./cmcumgr  -t 60 --conntype=serial --connstring="dev=/dev/ttyUSB0,baud=115200" reset
./cmcumgr analyze zephyr.signed.bin



tftp -gr zephyr.signed.bin 192.168.1.22
cmcumgr  -vvv --retries=5 --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" image upload zephyr.signed.bin
cmcumgr  --retries=5 --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" image upload zephyr.signed.bin
cmcumgr --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" image list
cmcumgr --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" image test 
cmcumgr  -t 60 --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" reset
cmcumgr --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" image confirm
cmcumgr  -t 60 --conntype=serial --connstring="dev=/dev/ttyS1,baud=115200" reset
cmcumgr analyze zephyr.signed.bin