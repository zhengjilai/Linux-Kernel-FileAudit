#!/bin/bash
# insmod
if [ -d "kernel" ]; then
   insmod kernel/fileauditzw.ko
fi
# start user file audit
if [ -d "user" ]; then
   ./user/cry.o
fi
