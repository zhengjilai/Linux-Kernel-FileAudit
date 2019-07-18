# FileAudit

## Brief Description

This project is a file audit based on linux system call overload. The basic functions are as follows:

1. In our project, there is a special folder called AUDIT. If you start our project on computer, the following things will happen.
2. Outside the AUDIT folder, nothing will be done respecting to our file audit.
3. Inside the AUDIT folder, you cannot access(including link, rm, open, read, write, ls, etc.) any of the files, except that we use our provided file audit box shell in ./user.
4. Besides, every file written in AUDIT folder with our file audit box shell will be encrypted by AES, so that other users cannot read plaintext without the decryption of our file audit box shell.

## How to use it

We provide three scripts for usage. 

1. install.sh helps you compile the C files. 
2. start.sh utilizes insmod to insert the kernel module into linux kernel as a linux rootkit, and it also starts the file audit box shell.
3. stop.sh utilized rmmod to remove the rootkit from linux kernel.

## Writers

Writers are as follows:

1. Jilai Zheng
2. Lei Wang
