# Linux Kernel FileAudit

## Brief Description

This project is a file audit based on linux system call override.

In our project, there is a special folder called AUDIT. If you run our project on your Linux machine, the following things will happen.

- Outside the AUDIT folder, nothing will be done respecting to our file audit.
- Inside the AUDIT folder, you cannot access (including link, rm, open, read, write, ls, etc.) any of the files, except that we use our provided file audit box shell in `./fileaudit/user`.
- Every file written in AUDIT folder with our file audit box shell will be encrypted by AES, so that other users cannot read plaintext without the decryption of our file audit box shell.
- You can cp file into or out of AUDIT folder with our file audit box shell, then the shell will encrypt or decrypt files automatically.

## Project Structure
```
├── fileaudit
│   ├── audit
│   ├── install.sh
│   ├── kernel
│   │   ├── fileauditzw.c
│   │   ├── LICENSE.txt
│   │   └── Makefile
│   ├── start.sh
│   ├── stop.sh
│   └── user
│       └── cryp-folder.c
├── README-en.md
└── README-zh.md
```

## Project Deployment

### Environment

Our experiment environment is listed as follows:

- Operating System: Ubuntu 16.04 LTS
- Linux Kernel: Linux 4.15.0-39-generic

Note that the kernel version is very important and sensitive. 
We have found that complilation can not be conducted properly with Linux kernel 5.0.0-37-generic.  

### Usage

Config the audit folder before compiling your kernel module, 
search the macro 'AUDIT\_PATH' in `./fileaudit/kernel/fileauditzw.c` and change its value to your wanted audit folder.

```shell
# define AUDIT_PATH "your_audit_folder"
```

We provide three shell scripts for usage.

- Shell script `install.sh` helps you compile the project. 

```shell
./install.sh
```

- Shell script `start.sh` utilizes insmod to insert the kernel module into linux kernel as a linux rootkit,
and it also starts a file audit box shell.

```shell
# Start the file audit box shell
sudo ./start.sh
# Exit the file audit box shell
exit
```

- Shell script `stop.sh` utilizes rmmod to remove the rootkit from linux kernel.
```shell
sudo ./stop.sh
```

## Contributors

Contributors are as follows:

- [Jilai Zheng](https://github.com/zhengjilai)
- [Lei Wang](https://github.com/Dulou)
