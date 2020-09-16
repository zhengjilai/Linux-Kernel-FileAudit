#!/bin/bash
exist=`lsmod | grep fileauditzw | wc -l`
if [ exist -ge 1 ]; then
    rmmod fileauditzw && echo "kernel module fileauditzw already removed" 
else
    echo "no module called fileauditzw in kernel"
fi
