#!/bin/bash
# insmod
if [ -d "kernel" ]; then
	insmod kernel/fileauditzw.ko || (echo "failed to insmod kernel module"; exit 1);
fi
# start user file audit
if [ -d "user" ]; then
    echo "begin to start fileaudit shell box"
    ./user/cry.o
fi
