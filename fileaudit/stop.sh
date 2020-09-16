#!/bin/bash
exist=`lsmod | grep fileauditzw | wc -l`
if [ "$exist" == "1" ]; then
    rmmod fileauditzw
    if [ "$?" -ne 0 ]; then 
        echo "Failed to rmmod fileauditzw from kernel, you may check permission" ; exit 1; 
    else
        echo "Successfully rmmod fileauditzw from kernel" 
    fi
else
    echo "No module called fileauditzw in kernel"
fi
