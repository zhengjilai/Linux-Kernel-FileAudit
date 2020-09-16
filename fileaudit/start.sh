#!/bin/bash
# insmod
if [ -d "kernel" ]; then
    insmod kernel/fileauditzw.ko 
    if [ "$?" -ne 0 ]; then echo "Failed to insmod kernel module" ; exit 1; fi
fi
# start user file audit
if [ -e "user/cry.o" ]; then
    echo "Begin to start fileaudit shell box"
    ./user/cry.o
fi
