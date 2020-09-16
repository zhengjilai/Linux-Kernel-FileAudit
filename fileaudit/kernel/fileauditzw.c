#define MAGIC_PREFIX "fileauditzw_secret"
#define MODULE_NAME "fileauditzw"

#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/string.h> 
#include <linux/sched/task.h>
#include <linux/list.h>
#include <linux/fs_struct.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	#include <linux/proc_ns.h>
#else
	#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	#include <linux/file.h>
#else
	#include <linux/fdtable.h>
#endif

#define AES_BLOCK_SIZE (16)
#define AES_IV_SIZE    (0)
#define AES_KEY_SIZE   (16) /*because we using ECB mode*/
#define AUDIT_PATH "/home/jlzheng/audit"
#define EXPECTED_PNAME "cry.o"
#define MAX_LENGTH 256
#define KEY_FILE "/tmp/tmp-key-cryp-folder"

// write tag
unsigned long cr0;
// system call table
static unsigned long *__sys_call_table;

// origin syscall
typedef asmlinkage int (*orig_open_t)(const char __user *filename, int flags, umode_t mode);
typedef asmlinkage ssize_t (*orig_read_t)(int __fd, void *__buf, size_t __nbytes);
typedef asmlinkage ssize_t (*orig_write_t)(int __fd, const void *__buf, size_t __n);
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *, unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int, struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_linkat_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags); 
typedef asmlinkage int (*orig_unlinkat_t)(int dirfd, const char *pathname, int flags);

orig_open_t orig_open;
orig_read_t orig_read;
orig_write_t orig_write;
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_linkat_t orig_linkat;
orig_unlinkat_t orig_unlinkat;

// the cipher_mode for AES
typedef enum {
	ENCRYPT,
	DECRYPT
} cipher_mode;

// define some functions implemented below
char *get_path(struct task_struct *mytask, int fd);
bool isInProtectedDir(char *directPath, char *protectedPath);
int getPIDwithProcessName(char *processName);
void get_fullname_from_relative(const char *pathname,char *fullname);
static int crypt_data(u8 *key, u32 key_len, u8 *iv, u32 iv_len, u8 *dst, u32 dst_len, u8 *src, u8 src_len, cipher_mode mode);


// get syscall table with sys_close
unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	unsigned long int i;
        // search sys_close to get sys_call_table
	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

// find the task struct
struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

// the hacked open, do some access control
asmlinkage long
hacked_open(const char __user *filename, int flags, umode_t mode)
{
    char *kfilename;
    int fd, pid, expectedpid;
    char *fullpath;    
    bool inProtectedDir, isFileBox;

    // malloc memory in kernal, use user memory results in failure
    kfilename = (char*)kmalloc(100, GFP_KERNEL);
    memset(kfilename, 0, 100);
    fullpath = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(fullpath, 0, MAX_LENGTH);
    // copy a string from user memory
    copy_from_user((char *)kfilename, filename, 100);
    
    // detect whether the path in the AUDIT_PATH
    get_fullname_from_relative(kfilename,fullpath);
    inProtectedDir = isInProtectedDir(fullpath,AUDIT_PATH);
    if (inProtectedDir && (flags & O_CREAT) != 0) {
        // printk("this file is indeed in %s \n", AUDIT_PATH);
        // if(fullpath != NULL) {printk("fullpath: %s\n", fullpath);}
        // determine if pid suits(in fileaudit box)
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        pid = current->pid;
        //printk("open:pid:%d,expectedpid:%d",pid,expectedpid);
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            // printk("hack opened %s\n", kfilename);
            // printk("pid:%d\n",pid);
            fd = orig_open(filename, flags, mode);
            return fd;
        } else{
            // in AUDIT_PATH but not in file box
            printk("open fail!!!!!");
            return -1;
        }     
    } else{ 
        // NOT IN AUDIT_PATH
        fd = orig_open(filename, flags, mode);
        return fd;
    }
    fd = orig_open(filename, flags, mode);
    return fd;
}

// the hacked read, used to encrypt
asmlinkage ssize_t
hacked_read (int __fd, void *__buf, size_t __nbytes)
{
    ssize_t res;
    
    struct task_struct *task = current;
    char *fullpath;
    bool inProtectedDir, isFileBox;
    int pid, expectedpid;
    int blockNumber; // number of blocks using AES
    char *cryPointer;
    unsigned char *key;
    int i, fd, err;
    mm_segment_t fs;
    u8 *iv,*src,*enc;    

    fullpath = get_path(task,__fd);
    inProtectedDir = isInProtectedDir(fullpath,AUDIT_PATH);
    
    if (inProtectedDir) {
        // expectedpid is the pid of the file box
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        // the pid of this process
        pid = current->pid;
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            res = orig_read(__fd, __buf, __nbytes);
            blockNumber = res / AES_BLOCK_SIZE;
            // printk("bytes:%ld, blocknumber:%d\n",res,blockNumber);
            if (res != 0){
                // cryPointer is the mirror of __buf in kernel
                cryPointer = (char*)kmalloc(res+1, GFP_KERNEL);
                memset(cryPointer, 0, res+1);
                // copy a string from user memory
                copy_from_user((char *)cryPointer, __buf, res);
                //printk("cryPointer:%s",cryPointer);
                
                //read key from file
                fs = get_fs();
	        set_fs(KERNEL_DS);
	        key = (unsigned char*)kmalloc(16, GFP_KERNEL);
	        memset(key, 0, 16);
	        fd = orig_open(KEY_FILE, O_RDONLY, 0664);
	        orig_read(fd, key, 16);
	        sys_close(fd);
                set_fs(fs);

                // kmalloc kernel space for iv, src and enc of AES
                iv = (unsigned char*)kmalloc(AES_IV_SIZE, GFP_KERNEL);
                memset(iv, 0, AES_IV_SIZE);
                src = (unsigned char*)kmalloc(blockNumber*AES_BLOCK_SIZE+1, GFP_KERNEL);
                memset(src, 0, blockNumber*AES_BLOCK_SIZE+1);
                enc = (unsigned char*)kmalloc(blockNumber*AES_BLOCK_SIZE+1, GFP_KERNEL);
                memset(enc, 0, blockNumber*AES_BLOCK_SIZE+1);
                strncpy(enc,cryPointer,blockNumber*AES_BLOCK_SIZE);
               
                // decrypt the first blockNumber blocks with AES
                err = crypt_data(key, AES_KEY_SIZE, iv, AES_IV_SIZE, src, blockNumber*AES_BLOCK_SIZE, enc, blockNumber*AES_BLOCK_SIZE, DECRYPT);
                // xor the last several bytes with key
                for (i = 0; i < res-AES_BLOCK_SIZE*blockNumber; i++){
                    cryPointer[AES_BLOCK_SIZE*blockNumber+i] = key[i] ^ cryPointer[AES_BLOCK_SIZE*blockNumber+i];
                }
                for (i = 0; i < AES_BLOCK_SIZE*blockNumber; i++){
                    cryPointer[i] = src[i];
                }
                // because buf is in user space
                copy_to_user(__buf,cryPointer,res);
            }
            return res;
        } else{printk("read fail!!!!!");return 0;}
    } 
    res = orig_read(__fd, __buf, __nbytes);
    return res;
}

// the hacked write, used to decrypt
asmlinkage ssize_t
hacked_write (int __fd, const void *__buf, size_t __n)
{
    ssize_t res;

    struct task_struct *task = current;
    char *fullpath;
    bool inProtectedDir, isFileBox;
    int pid, expectedpid;
    int blockNumber; // number of blocks using AES
    char *cryPointer;
    unsigned char *key;
    int i, fd, err;
    mm_segment_t fs;
    u8 *iv,*enc,*src;

    // judge whether the file is in AUDIT_PATH
    fullpath = get_path(task,__fd);
    inProtectedDir = isInProtectedDir(fullpath,AUDIT_PATH);

    if (inProtectedDir) {
        // judge whether in file box
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        pid = current->pid;
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            blockNumber = __n / AES_BLOCK_SIZE;      
            if (__n != 0){
                // cryPointer is the mirror of __buf in kernel
                cryPointer = (char*)kmalloc(__n+1, GFP_KERNEL);
                memset(cryPointer, 0, __n+1);
                // copy a string from user memory
                copy_from_user((char *)cryPointer, __buf, __n);

                //read key from file
                fs = get_fs();
                set_fs(KERNEL_DS);
                key = (unsigned char*)kmalloc(16, GFP_KERNEL);
                memset(key, 0, 16);
                fd = orig_open(KEY_FILE, O_RDONLY, 0664);
                orig_read(fd, key, 16);
                sys_close(fd);
                set_fs(fs);

                // kmalloc kernel space for iv, src and enc of AES
                iv = (unsigned char*)kmalloc(AES_IV_SIZE, GFP_KERNEL);
                memset(iv, 0, AES_IV_SIZE);
                enc = (unsigned char*)kmalloc(blockNumber*AES_BLOCK_SIZE+1, GFP_KERNEL);
                memset(enc, 0, blockNumber*AES_BLOCK_SIZE+1);
                src = (unsigned char*)kmalloc(blockNumber*AES_BLOCK_SIZE+1, GFP_KERNEL);
                memset(src, 0, blockNumber*AES_BLOCK_SIZE+1);

                strncpy(src,cryPointer,blockNumber*AES_BLOCK_SIZE);
                // encrypt with AES
                err = crypt_data(key, AES_KEY_SIZE, iv, AES_IV_SIZE, enc, blockNumber*AES_BLOCK_SIZE, src, blockNumber*AES_BLOCK_SIZE, ENCRYPT);
                // xor the last several bytes with key
                for (i = 0; i < __n - AES_BLOCK_SIZE*blockNumber; i++){
                    cryPointer[AES_BLOCK_SIZE*blockNumber+i] = key[i] ^ cryPointer[AES_BLOCK_SIZE*blockNumber+i];
                }
                for (i = 0; i < AES_BLOCK_SIZE*blockNumber; i++){
                    cryPointer[i] = enc[i];
                }
                // write file with ENCRYPTED data
		fs = get_fs();
                set_fs(KERNEL_DS); // set write buf to kernel
                res = orig_write(__fd, cryPointer, __n);
		set_fs(fs); // set back
            }else {res = orig_write(__fd, __buf, __n);}
            return res;
        } else{printk("write fail!!!!!");return -1;}
    }
    res = orig_write(__fd, __buf, __n);
    return res;
}

// the hacked getdent
asmlinkage int
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{   
    int res;
    struct task_struct *task = current;
    char *fullpath;
    bool inProtectedDir, isFileBox;
    int pid, expectedpid;

    fullpath = get_path(task,fd);
    inProtectedDir = isInProtectedDir(fullpath,AUDIT_PATH);

    if (inProtectedDir) {
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        pid = current->pid;
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            res = orig_getdents(fd, dirent, count);
            return res;
        } else{printk("getdent fail!!!!!");return 0;}
    }
 
    res = orig_getdents(fd, dirent, count);
    return res;
}

// the hacked getdent64
asmlinkage int
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    int res;
    struct task_struct *task = current;
    char *fullpath;
    bool inProtectedDir, isFileBox;
    int pid, expectedpid;

    fullpath = get_path(task,fd);
    inProtectedDir = isInProtectedDir(fullpath,AUDIT_PATH);

    if (inProtectedDir) {
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        pid = current->pid;
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            res = orig_getdents64(fd, dirent, count);
            return res;
        } else{printk("getdent64 fail!!!!!");return 0;}
    }

    res = orig_getdents64(fd, dirent, count);
    return res;
}

// the hacked linkat, used to ban 'ln'
asmlinkage int 
hacked_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    int res;
    char *koldpath, *knewpath, *fullpathOld, *fullpathNew;
    bool inProtectedDirOld, inProtectedDirNew, isFileBox;
    int pid, expectedpid;

    // kmalloc and copy the oldpath and newpath from user to kernel
    koldpath = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(koldpath, 0, MAX_LENGTH);
    knewpath = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(knewpath, 0, MAX_LENGTH);
    fullpathOld = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(fullpathOld, 0, MAX_LENGTH);
    fullpathNew = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(fullpathNew, 0, MAX_LENGTH);

    copy_from_user((char *)koldpath, oldpath, MAX_LENGTH);
    copy_from_user((char *)knewpath, newpath, MAX_LENGTH);
    // get the full path through oldpath and newpath
    get_fullname_from_relative(koldpath,fullpathOld);
    get_fullname_from_relative(knewpath,fullpathNew);
	
    inProtectedDirOld = isInProtectedDir(fullpathOld,AUDIT_PATH);
    inProtectedDirNew = isInProtectedDir(fullpathNew,AUDIT_PATH);
    // if this link operation relates to AUDIT_PATH	
    if (inProtectedDirOld || inProtectedDirNew) {
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        pid = current->pid;
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            res = orig_linkat(olddirfd,oldpath,newdirfd,newpath,flags);
            return res;
        } else{printk("linkat fail!!!!!");return -1;}
    }

    res = orig_linkat(olddirfd,oldpath,newdirfd,newpath,flags);
    return res;
}

// the hacked unlinkat, used to ban 'rm'
asmlinkage int
hacked_unlinkat(int dirfd, const char *pathname, int flags)
{
    int res;
    char *kpathname, *kfullpath;
 
    bool inProtectedDir, isFileBox;
    int pid, expectedpid;
    
    // kmalloc kernel space for kpathname
    kpathname = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(kpathname, 0, MAX_LENGTH);
    kfullpath = (char*)kmalloc(MAX_LENGTH, GFP_KERNEL);
    memset(kfullpath, 0, MAX_LENGTH);
    
    copy_from_user((char *)kpathname, pathname, MAX_LENGTH);
    
    get_fullname_from_relative(kpathname,kfullpath);
    
    inProtectedDir = isInProtectedDir(kfullpath,AUDIT_PATH);

    if (inProtectedDir) {
        expectedpid = getPIDwithProcessName(EXPECTED_PNAME);
        pid = current->pid;
        isFileBox = (pid==expectedpid);
        if (isFileBox){
            res = orig_unlinkat(dirfd, pathname, flags);
            return res;
        } else{printk("unlinkat fail!!!!!");return -1;}
    }
    res = orig_unlinkat(dirfd, pathname, flags);
    return res;
}

// add write protect
static inline void
protect_memory(void)
{
	write_cr0(cr0);
}

// remove write protect
static inline void
unprotect_memory(void)
{
	write_cr0(cr0 & ~0x00010000);
}

// get the direct path to the file with its fd
char *get_path(struct task_struct *mytask, int fd) 
{
    struct file *myfile = NULL; 
    struct files_struct *files = NULL;
    char *ppath;
    ppath = (char*)kmalloc(200, GFP_KERNEL);
    memset(ppath, 0, 200);

    files = mytask->files; 
    if (!files) {
        printk("files is null..\n"); 
        return NULL;
    } 
    myfile = files->fdt->fd[fd];
    if (!myfile) { 
        printk("myfile is null..\n");
        return NULL; 
    } 
    ppath = d_path(&(myfile->f_path), ppath, 200); 
    return ppath; 
}

// get fullname from relative pathname
void get_fullname_from_relative(const char *pathname,char *fullname)
{
	struct dentry *tmp_dentry = current->fs->pwd.dentry;
	char tmp_path[MAX_LENGTH];
	char local_path[MAX_LENGTH];
	memset(tmp_path,0,MAX_LENGTH);
	memset(local_path,0,MAX_LENGTH);

	if (*pathname == '/') {
		strcpy(fullname,pathname);
		return;
	}

	while (tmp_dentry != NULL)
	{
		if (!strcmp(tmp_dentry->d_iname,"/"))
			break;
		strcpy(tmp_path,"/");
		strcat(tmp_path,tmp_dentry->d_iname);
		strcat(tmp_path,local_path);
		strcpy(local_path,tmp_path);

		tmp_dentry = tmp_dentry->d_parent;
	}
	strcpy(fullname,local_path);
	strcat(fullname,"/");
	strcat(fullname,pathname);
	return;
}

// judge whether the file is in the protected DIR
bool isInProtectedDir(char *directPath, char *protectedPath){
    int protlen;
    
    protlen = strlen(protectedPath);
    return (strncmp(directPath,protectedPath,protlen) == 0);
} 

// get pid with p name
int getPIDwithProcessName(char *processName){
    struct task_struct *p, *ts = &init_task;
    struct list_head *pos;
    // first search parent's parent's pid, like cat
    list_for_each(pos, &ts->tasks) {
        p = list_entry(pos, struct task_struct,tasks);
        if (strcmp(p->parent->parent->comm,processName)==0){
            return p->pid;
        }  
    }
    // second search parent's pid, like echo xxx > yyy
    ts = &init_task;
    list_for_each(pos, &ts->tasks) {
        p = list_entry(pos, struct task_struct,tasks);
        if (strcmp(p->parent->comm,processName)==0){
            return p->pid;
        }           
    }
    return -1;
}

// the function for decrypt and encrypt
// use linux kernel module <linux/crypto.h>
static int crypt_data(u8 *key, u32 key_len, u8 *iv, u32 iv_len, u8 *dst, u32 dst_len, u8 *src, u8 src_len, cipher_mode mode)
{
	struct crypto_blkcipher * blk;
	struct blkcipher_desc desc;
	struct scatterlist sg[2];

    /*CRYPTO_ALG_TYPE_BLKCIPHER_MASK, CRYPTO_ALG_TYPE_BLKCIPHER*/
	blk = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
	if (IS_ERR(blk)) {
		printk(KERN_ALERT "Failed to initialize AES-XTS mode \n");
		return -1;
	} else {
		printk(KERN_ALERT "Initialized cipher: %s \n", crypto_blkcipher_name(blk));
		printk(KERN_ALERT "with IV size: %d \n", crypto_blkcipher_ivsize(blk));
		printk(KERN_ALERT "block size: %d \n", crypto_blkcipher_blocksize(blk));
	}

	if(crypto_blkcipher_setkey(blk, key, key_len)) {
		printk(KERN_ALERT "Failed to set key. \n");
		goto err;
	}

	crypto_blkcipher_set_iv(blk, iv, iv_len);

	sg_init_one(&sg[0],src,src_len);
	sg_init_one(&sg[1],dst,dst_len);

	/* do encryption */
	desc.tfm = blk;
	desc.flags = 0;

	if(mode == ENCRYPT) {
		if(crypto_blkcipher_encrypt(&desc, &sg[1], &sg[0], src_len)) {
			printk(KERN_ALERT "Failed to encrypt. \n");
		}
	} else {
		if(crypto_blkcipher_decrypt(&desc, &sg[1], &sg[0], src_len)) {
			printk(KERN_ALERT "Failed to encrypt. \n");
		}
	}
	
	crypto_free_blkcipher(blk);
	return 0;

err:
	
	crypto_free_blkcipher(blk);
	return -1;
}

// the init function
static int __init
fileauditzw_init(void)
{
        // get system call table
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;
        // get write protect bit
	cr0 = read_cr0();

        // get the original system calls
	orig_open = (orig_open_t)__sys_call_table[__NR_open];
	orig_read = (orig_read_t)__sys_call_table[__NR_read];
	orig_write = (orig_write_t)__sys_call_table[__NR_write];
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_linkat = (orig_linkat_t)__sys_call_table[__NR_linkat];
	orig_unlinkat = (orig_unlinkat_t)__sys_call_table[__NR_unlinkat];
        
        // overlay the orig, set them to hacked functions
	unprotect_memory();
	__sys_call_table[__NR_open] = (unsigned long)hacked_open;
	__sys_call_table[__NR_read] = (unsigned long)hacked_read;
	__sys_call_table[__NR_write] = (unsigned long)hacked_write;
	__sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
	__sys_call_table[__NR_linkat] = (unsigned long)hacked_linkat;
	__sys_call_table[__NR_unlinkat] = (unsigned long)hacked_unlinkat;
	protect_memory();

	return 0;
}

// the exit function
static void __exit
fileauditzw_cleanup(void)
{
        // recover the system call table
	unprotect_memory();
	__sys_call_table[__NR_open] = (unsigned long)orig_open;
	__sys_call_table[__NR_read] = (unsigned long)orig_read;
	__sys_call_table[__NR_write] = (unsigned long)orig_write;
	__sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	__sys_call_table[__NR_linkat] = (unsigned long)orig_linkat;
	__sys_call_table[__NR_unlinkat] = (unsigned long)orig_unlinkat;
	protect_memory();
}

module_init(fileauditzw_init);
module_exit(fileauditzw_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("zjl&wl");
MODULE_DESCRIPTION("fileauditzw");

