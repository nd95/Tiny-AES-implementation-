In this version of Kokke's tiny AES implementation
My partner and I decided to change things up and try to use input files with hex as input instead of small hex numbers!

Our end goal is to try and parallelize it using OPENMP but at the moment we want our files to be bigger than 6400000.

Creating files and testing them with sizes upto 64000000 works perfectly fine. However a segmentation fault occurs when trying to create a larger file.

to run the program run make

then ./test-elf N

where N is a file size of either 64,640,6400,64000,640000,64000000.

In our folder we have multiple test files which were previously encrypted and decrypted. They consist of different sizes.

The naming convention for these files goes as:

Bytes_d for decrypted or e for encrypted_ aes function name.data

For example: 
64_d_ctr.data

A 64 byte decrypted file used for ctr function in the program.

The file ENCRYPTEDSCRIPT.data is the script made during execution for a method. We used this file to compare it to the already created file associated with that size.

-- FOR SCIENCE!!