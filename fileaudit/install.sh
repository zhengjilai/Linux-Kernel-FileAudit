#!/bin/bash
# compile kernel module
if [ -d "kernel" ]; then
    echo "Begin to compile kernel module."
    cd kernel && make clean || (echo "Make clean kernel module failed."; exit 1);
    make || (echo "Make kernel module failed."; exit 1);
fi
# compile user module
if [ -d "../user" ]; then 
    echo "Begin to compile user file audit." && cd ..
    gcc ./user/cryp-folder.c -o ./user/cry.o -lcrypto || (echo "Make user file audit failed."; exit 1); 
fi

