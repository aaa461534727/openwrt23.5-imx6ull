#ifndef SSL_H
#define SSL_H 1

#include <string.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define SSL_KEY  "zcklstudiocsgxhc"
#define SSL_IV   "2012518884042021"
#define BLOCK_SIZE 16



extern char * ssl_base64_encode(const unsigned char *input,int length, int *out_len);
extern char * ssl_base64_decode(const unsigned char *input, int length, int *out_len);
extern  int ssl_aes_encode(const unsigned char *input,const unsigned char *output,int len);
extern  int ssl_aes_decrypt(const unsigned char *input,const unsigned char *output,int len);
extern int aes_encrypt_pkcs5pading(unsigned char *sz_in_buff, int sz_in_len, unsigned char *key,unsigned char *iv, unsigned char *out_buff, int out_len);
extern int aes_decrypt_pkcs5pading(unsigned char *sz_in, int in_len, unsigned char *key,unsigned char *iv, unsigned char *out_buff, int out_len);
#endif
