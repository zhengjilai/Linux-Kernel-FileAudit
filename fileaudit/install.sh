cd kernel
sudo make clean
sudo make
cd ..
cd user
gcc cryp-folder.c -o cry.o -lcrypto
cd ..
