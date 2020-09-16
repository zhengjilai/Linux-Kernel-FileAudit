#!/bin/bash
# compile kernel module
if [ -d "kernel" ]; then
    echo "Begin to compile kernel module."
    cd kernel && make clean 
    if [ "$?" -ne 0 ]; then echo "Clean kernel module materials failed."; exit 1; fi
    make
    if [ "$?" -ne 0 ]; then echo "Compile kernel module failed."; exit 1; fi
fi
# compile user module
if [ -d "../user" ]; then 
    echo "Begin to compile user file audit." && cd ..
    gcc ./user/cryp-folder.c -o ./user/cry.o -lcrypto
    if [ "$?" -ne 0 ]; then echo "Compile user file audit failed."; exit 1; fi 
fi

