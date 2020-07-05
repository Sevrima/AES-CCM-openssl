first openssl library needs to be installed (unfortunately it is bulky!)

1- to get the pakage: "git clone https://github.com/openssl/openssl.git"
2- go into the openssl folder
3- run "./config" 
4- run "sudo make"
5- run "sudo make install"
6- use the "gcc *.c -o out.exe -lcrypto" command to compile the aes-gcm code