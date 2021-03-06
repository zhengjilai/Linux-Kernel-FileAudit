# FileAudit

## 项目简介

本项目是上海交通大学信息安全专业2015级”系统软件课程设计“的课程大作业——加密型文件保险箱。其满足的主要功能包括：

1. 指定操作系统中的一个目录为受保护目录，那么除本保险箱的用户程序外的任何进程不能访问受保护目录，且不能对受保护目录内的文件进行增删改查等各种操作
2. 用户可以通过注册和登录使用本保险箱的用户程序。登录用户程序后，可以对受保护目录的文件进行增删改查等操作，还可通过cp命令将文件放入或取出文件保险箱
3. 需要注意的是，放入受保护目录中的文件在磁盘上全部加密保存，只有在用户程序下查看文件才是解密状态

## 使用说明

本项目开发及测试环境均为 Ubuntu 16.04 LTS，内核版本为 Linux 4.15.0-39-generic。在开发及测试环境中运行正常，但不保证在更高版本 Linux 内核中可以正常运行。

### 文件介绍

本项目文件目录树如下：
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
其中kernel文件夹为内核代码，user 文件夹为用户程序代码，install.sh、start.sh 和 stop.sh 三个 shell 脚本便于编译和启动程序。

### 使用方法

在开始使用之前，首先配置需要 audit 的文件夹，需要在 kernel/fileauditzw.c 中搜索宏定义 AUDIT_PATH 并修改为 AUDIT 文件夹的绝对路径

```shell
 # define AUDIT_PATH "your_audit_folder"
```

本项目是命令行界面。进入文件夹目录，依次执行以下命令

```shell
./install.sh
```

该命令编译内核代码为可装载的内核模块，编译用户代码为可执行的用户程序。

```shell
sudo ./start.sh
```

该命令装载编译好的内核模块到操作系统，并启动用户程序。此时出现用户程序的注册和登录提示，依提示注册登录后即进入用户程序，可执行各种命令进行操作。

若执行完命令要退出程序，最好不要使用 Ctrl+C 的方式退出以免出现问题。用户程序提供了退出命令

```shell
exit
```

退出程序后若要卸载装载的内核模块，可直接运行

```shell
sudo ./stop.sh
```

此时内核模块即被卸载，系统恢复原样。

若出现以上 shell 命令无法执行的情况，可尝试修改 shell 文件的执行权限

```shell
chmod 775 install.sh start.sh stop.sh
```

## 作者信息

1. 郑继来 	
2. 王  磊
