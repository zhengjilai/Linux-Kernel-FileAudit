#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "openssl/sha.h"

#define PWD_FILE "/tmp/passwd-cryp-folder"
#define TMP_KEY_FILE "/tmp/tmp-key-cryp-folder"

// do sha256 algorithm to save passwd
// use openssl/sha.h
char * do_sha256(char* s, char *res)
{
	unsigned char md[33]={0};
    	char tmp[3] = {0};
	int i;
	
	SHA256(s, strlen(s), md);
	for(i = 0; i < 32; i++ )
	{
        	sprintf(tmp,"%02x", md[i]);
        	strcat(res, tmp);
    	}
	return res;
}

// register when first use 
void register_program() 
{
	char valid_pwd[21]={0};
	char pwd[21]={0};
	char tmp[21] = {0};
	char *sha256_pwd;

	FILE *file;
	
	// input passwd
	do {
		printf("Please input your password ( length <= 20 ):\n");
		// not display your input in commandline
		system("stty -echo");
		scanf("%s",pwd);
		printf("\n");
		printf("Please input your password again to valid it:\n");
		scanf("%s",valid_pwd);
		printf("\n");
                // recover commandline display
		system("stty echo");
		if (strcmp(pwd, valid_pwd) != 0) {
			printf("Two passwords not equal! Please try again!\n");		
		}
	} while(strcmp(pwd, valid_pwd));
	
	sha256_pwd = malloc(65);
	do_sha256(pwd, sha256_pwd);
	printf("SHA256(your passwd):%s\n", sha256_pwd);
	
        // save sha256(passwd) to file PWD_FILE
	file = fopen(PWD_FILE, "w");
	fputs(sha256_pwd, file);
	fclose(file);
}

// login after you have registered
int login()
{
	FILE *file;
	char buf[65];
	char *read_sha256;
	char *sha256_pwd;
	char pwd[21]={0};
	int i;
	
        // read sha256(passwd) from saved file
	file = fopen(PWD_FILE, "r");
	read_sha256 = fgets(buf, 65, file);
	fclose(file);

	sha256_pwd = malloc(65);
	
	printf("Please login Cryp-folder.\n");
	printf("Please input your password.\n");
	
	// input passwd to login and give three chances to fail
	system("stty -echo");	
	for (i=0;i<3;i++)
	{
		memset(sha256_pwd, 0, 65);
		scanf("%s", pwd);
		printf("\n");
		do_sha256(pwd, sha256_pwd);
		if (!strcmp(read_sha256, sha256_pwd))
		{
			system("stty echo");
			printf("\033[1;32mLogin Successfully!\n\033[0m");
			return 0;
		}
		else
		{
			printf("Password error! This is your %dth try!\n", i+1);
			if (i==2) { printf("\033[1;31mLogin fail!\n\033[0m"); }
			else {printf("Please input your password again.\n");}			
		}		
	}
	system("stty echo");
	return -1;
}

// produce cipher key for file encryption/decryption
// use sha256(passwd) to produce random num
unsigned char* create_key(unsigned char* key)
{
	FILE *file;
	char *sha256_pwd;
	char buf[65];
	int i;
	unsigned int seed = 0;

	file = fopen(PWD_FILE, "r");
	sha256_pwd = fgets(buf, 65, file);
	fclose(file);
	
	for (i=0;i<64;i++)
	{	
		seed += sha256_pwd[i];	
	}
	seed *= 2;

	srand(seed);
	for (i=0;i<16;i++)
	{
		*(key+i) = (unsigned char)(rand()%256);
	}
	
	return key;
}

int main() {
	int login_succ_tag;
	unsigned char *key;
	FILE *file;
	char cmd[100], tmpcmd[100];
	char *path = NULL;
	char *p;

	// check whether registered and do registration if not	
	if (access(PWD_FILE, 0))
	{
		printf("We find you haven't registered cryp-folder now.\n");
		printf("Please register it now to use program.\n");
		register_program();
	}
	
        // login
	login_succ_tag = login();
	
        // login successfully
	if(!login_succ_tag) {
                // create cipher key and save it to TMP_KEY_FILE
		key = (unsigned char*)malloc(16);
		memset(key, 0, 16);
		create_key(key);
	
		file = fopen(TMP_KEY_FILE, "w");
		fwrite(key, 1, 16, file);
		fclose(file);
		
                // get current filepath	
		path = getcwd(NULL, 0);
		
		// clear out stdin buf
		setbuf(stdin, NULL);
		while(1) 
		{
			printf("> %s: ", path);
                        // get input command
			fgets(cmd, 100, stdin);
			cmd[strlen(cmd)-1] = 0;	
			
                        // set "exit" command to quit this program
			if(!strcmp(cmd,"exit")) {
				memset(cmd, 0, 100);

                                // remove TMP_KEY_FILE
				strcpy(cmd, "rm ");
				strcat(cmd, TMP_KEY_FILE);
				system(cmd);
				break;
			}
			else { 
                                // check whether change filepath
				strcpy(tmpcmd, cmd);
				p = strtok(tmpcmd, " ");
                                // if change, use chdir() to change
                                // because system() can't run "cd"
				if (!strcmp(p,"cd")) 
				{
					p=strtok(NULL," ");
					if(p) 
					{
						chdir(p);
						getcwd(path, 255);
					}		
				}
				else {
					system(cmd);
				}
			}
		}
	}
	return 0;
}
