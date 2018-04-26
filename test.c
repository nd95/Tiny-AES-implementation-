#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"
#include "omp_timer.h"


static void test_encrypt_ecb(int size);
static void test_xcrypt_ctr(int size);


int main(int argc, char** argv)
{

#ifdef AES128
    printf("\nTesting AES128\n\n");
#endif
 
    int size = atoi(argv[1]);

    printf("ctr\n");
    test_xcrypt_ctr(size);
    printf("ecb\n");
    test_encrypt_ecb(size);


    return 0;
}

static void test_xcrypt_ctr(int size)
{

    char * desired_output = ""; //this file has the desired output
    char * e_fname = "ENCRYPTEDSCRIPT.data"; //this file has the encrypted data that is created in this script
    uint8_t in[size];

    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

    uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

    for(int i = 0; i < size; i++)
    {
        in[i] = 0x6b;
    }

   
    switch(size) 
    {
      case 64 :
        desired_output = "64_e_ctr.data";
         break;
      case 640 :
         desired_output = "640_e_ctr.data";
         break;
      case 6400 :
         desired_output = "6400_e_ctr.data";
         break;
      case 64000 :
         desired_output = "64000_e_ctr.data";
         break;
      case 640000:
         desired_output = "640000_e_ctr.data";
         break;
      case 6400000:
          desired_output = "6400000_e_ctr.data";
        break;
      case 64000000:
          desired_output = "64000000_e_ctr_ERRORFILE.data";
        break;      
              
      default :
         printf("Invalid\n" );
    }
   

    
    struct AES_ctx ctx;

    START_TIMER(e_ctr)

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, in, size);

    STOP_TIMER(e_ctr)


    //un comment this section to create the errorfile
    //FILE *f1 = fopen("64000000_e_ctr_ERRORFILE.data", "wb");
	//fwrite(in, 1, sizeof(in), f1);
	//fclose(f1);

    FILE *f = fopen(e_fname, "wb");   
    fwrite(in, 1 , sizeof(in), f);
    fclose(f);

  
     if(compare(desired_output, e_fname) == 1)
     {
         printf("SUCCESS!\n");
         printf("Nthreads=%2d  \n e_ctr: %8.9fs \n",1, GET_TIMER(e_ctr));
     }
     else
     {
         printf("FAILURE!\n");
     }
}



static void test_encrypt_ecb(int size)
{


    char * desired_output = ""; //this file has the desired output
    char * e_fname = "ENCRYPTEDSCRIPT_ECB.data"; //this file has the encrypted data that is created in this script
    uint8_t in[size];
   
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    switch(size) 
    {
      case 64 :
        desired_output = "64_e_ecb.data";
         break;
      case 640 :
         desired_output = "640_e_ecb.data";
         break;
      case 6400 :
         desired_output = "6400_e_ecb.data";
         break;
      case 64000 :
         desired_output = "64000_e_ecb.data";
         break;
      case 640000:
         desired_output = "640000_e_ecb.data";
         break;
      case 6400000:
          desired_output = "6400000_e_ecb.data";
        break;   
      case 64000000:
          desired_output = "64000000_e_ecb_ERRORFILE.data";
        break;      
      default :
         printf("Invalid\n" );
    }

    for(int i = 0; i < size; i++)
    {
        in[i] = 0x6b;
    }

    struct AES_ctx ctx;

    START_TIMER(e_ecb)

    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, in);

    STOP_TIMER(e_ecb)


    /** UNCOMMENT THIS SECTION TO CREATE 64000000 FILE SIZE TO TEST
    FILE *f1 = fopen("64000000_e_ecb_ERRORFILE.data", "wb");
	fwrite(in, 1, sizeof(in), f1);
	fclose(f1);
    **/

    
    FILE *f = fopen(e_fname, "wb");   
    fwrite(in, 1 , sizeof(in), f);
    fclose(f);

    printf("ECB encrypt: ");

    if(compare(desired_output, e_fname) == 1)
    {
        printf("SUCCESS!\n");
        printf("Nthreads=%2d  \n e_ecb: %8.9fs \n",1, GET_TIMER(e_ecb));
    }
    else
    {
         printf("FAILURE!\n");
    }

    
}



static void test_decrypt_ecb(void)
{
#ifdef AES128
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t in[]  = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
#elif defined(AES192)
    uint8_t key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                      0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t in[]  = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
#elif defined(AES256)
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t in[]  = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
#endif

    uint8_t out[]   = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    struct AES_ctx ctx;
    
    AES_init_ctx(&ctx, key);
    AES_ECB_decrypt(&ctx, in);

    printf("ECB decrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

/**
*https://cboard.cprogramming.com/c-programming/97903-binary-comparison-2-files.html
*
*/
int compare(char * f1name, char * f2name)
{
  FILE *file1, *file2;
 
  char c1, c2;
  unsigned long int errors = 0;
  unsigned long int count = 0;
  int file1ok, file2ok;
 
  printf("\n\n");
  /* while(--argc > 0)
      printf("&#37;s\n", argv[argc]);
  */
  file1 = fopen(f1name, "rb");
  file2 = fopen(f2name, "rb");
 
  if(file1 == NULL)
  {
    printf("Error: can't open file number one.\n");
  }
  if(file2 == NULL)
  {
    printf("Error: can't open file number two.\n");
  }
  else
  {
     while(1)
     {
        file1ok = fread(&c1, sizeof(char), 1, file1);
        file2ok = fread(&c2, sizeof(char), 1, file2);
       
    if(file1ok && file2ok)
    {
       if((c1 ^ c2) != 0)
          errors++;
          count++;
          // printf(" %c",  c1);
    }
    else
            break;
     } /* end of while */
 
     fclose(file1);
     fclose(file2);
     printf("\nResult: %lu bits compared. %lu equal bits found\n\n", count, count-errors);

     if(errors == 0)
     {
        return 1;//return true that there are no errors and they are both matching
     }
     else
     {
        return 0;
     }
 
  } /* end of else */
 
   
   return 0;
}
