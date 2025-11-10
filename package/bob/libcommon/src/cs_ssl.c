#include "cs_ssl.h"

#define dbg(fmt, args...) do { FILE *fp = fopen("/dev/console", "w"); if (fp) { fprintf(fp, "[%s:%d] " fmt,__FUNCTION__ , __LINE__, ## args); fclose(fp); } else fprintf(stderr, fmt, ## args); } while (0)


//#if (SSL_H == 1)
int parse_space_str(char *str,char *result,int len)
{
	char pt = 0x20; 
	char buf[1024] = {0},buffer[1024] = {0};
	int i,j;
	char ch;
	strncpy(buf,str,len);
	i = 0;j = 0;

	//Remove values without graphics
	while(buf[i] > pt){
		ch = buf[i];
		buffer[j] = ch;
		i++;
		j++;
	}

	strncpy(result,buffer,strlen(buffer));
	return 0;
}

char * ssl_base64_encode(const unsigned char *input,int length, int *out_len)
{
	BIO *bmem = NULL;
	BIO *b64 = NULL;
	BUF_MEM *bptr;

	if (input == NULL)
		return NULL;

	b64 = BIO_new(BIO_f_base64());         
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());    
	b64 = BIO_push(b64, bmem);    
	BIO_write(b64, input, length);    
	BIO_flush(b64);    
	BIO_get_mem_ptr(b64, &bptr);   
	BIO_set_close(b64, BIO_NOCLOSE);    
	char *buff = (char *)malloc(bptr->length + 1);    
	memcpy(buff, bptr->data, bptr->length);    
	buff[bptr->length] = 0;    
	BIO_free_all(b64);

	*out_len = bptr->length;
	return buff;
}

char * ssl_base64_decode(const unsigned char *input, int length, int *out_len)
{
	if (input == NULL)
		return NULL;
	
	BIO *b64 = NULL;
	BIO *bmem = NULL;
	char *buffer = (char *)malloc(length);   
	memset(buffer, 0, length);    
	b64 = BIO_new(BIO_f_base64());   
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);    
	bmem = BIO_new_mem_buf(input, length);    
	bmem = BIO_push(b64, bmem);    
	int len = BIO_read(bmem, buffer, length);    
	BIO_free_all(bmem);
	
	*out_len = len;
	return buffer;
}

int aes_encrypt_pkcs5pading(unsigned char *sz_in_buff, int sz_in_len, unsigned char *key,
		unsigned char *iv, unsigned char *out_buff, int out_len)
{
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	int isSuccess = 0;
	unsigned char in[BLOCK_SIZE];
	unsigned char sz_out_buff[65535] = {0};
	int outl = 0;
	int outl_total = 0;
	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);    

	while(sz_in_len >=BLOCK_SIZE) {
		memcpy(in, sz_in_buff, BLOCK_SIZE);
		sz_in_len -= BLOCK_SIZE;
		sz_in_buff += BLOCK_SIZE;
		isSuccess = EVP_EncryptUpdate(ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);             
		if(!isSuccess) {
			dbg("EVP_EncryptUpdate() failed\n");
			EVP_CIPHER_CTX_cleanup(ctx);
			return -1;
		}
		outl_total += outl;
	}

	if(sz_in_len > 0){
		memcpy(in, sz_in_buff, sz_in_len);
		isSuccess = EVP_EncryptUpdate(ctx, sz_out_buff + outl_total, &outl, in, sz_in_len); 
		outl_total += outl;
		isSuccess = EVP_EncryptFinal_ex(ctx, sz_out_buff + outl_total, &outl);
		if(!isSuccess) {
			dbg("EVP_EncryptFinal_ex() failed\n");
			EVP_CIPHER_CTX_cleanup(ctx);
			return -1;
		}
		outl_total += outl;
	}

	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);

	int b64_len = 0;
	char *b64_encode =  ssl_base64_encode(sz_out_buff, outl_total, &b64_len);
	if(b64_len > 0 && b64_len < out_len){
		snprintf((char *)out_buff, out_len, "%s", b64_encode);
		free(b64_encode);
	}
	else
		return -1;
	
	return outl_total;
}


int aes_decrypt_pkcs5pading(unsigned char *sz_in, int in_len, unsigned char *key,
		unsigned char *iv, unsigned char *out_buff, int out_len){
	unsigned char in[BLOCK_SIZE];
	unsigned char sz_out_buff[65536] = {0};
	int outl = 0;
	int outl_total = 0;
	int isSuccess;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();

	int sz_in_length = 0;
	char * sz_in_buff = ssl_base64_decode(sz_in, in_len, &sz_in_length);
	if(sz_in_length == 0 || NULL == sz_in_buff)
		 return -1;

	char * sz_in_decode = NULL;   
	sz_in_decode = sz_in_buff ;

	isSuccess = EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,iv);
	if(!isSuccess){              
		dbg("EVP_DecryptInit_ex() failed\n");              
		EVP_CIPHER_CTX_cleanup(ctx);              
		return -1;          
	} 

	EVP_CIPHER_CTX_set_padding(ctx, 0);
	while(sz_in_length >BLOCK_SIZE)
	{
		memcpy(in, sz_in_buff, BLOCK_SIZE);
		sz_in_length -= BLOCK_SIZE;
		sz_in_buff += BLOCK_SIZE;
		isSuccess = EVP_DecryptUpdate(ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);
		if(!isSuccess)
		{
			dbg("EVP_DecryptUpdate() failed\n");
			EVP_CIPHER_CTX_cleanup(ctx);
			return -1;
		}
		outl_total += outl;
	}    

	if(sz_in_length > 0)
	{
		memcpy(in, sz_in_buff, sz_in_length);
		isSuccess = EVP_DecryptUpdate(ctx, sz_out_buff+outl_total, &outl, in, sz_in_length);
		if(!isSuccess)
		{
			dbg("sz_in_length<BLOCK_SIZE: EVP_DecryptUpdate() failed\n");
			EVP_CIPHER_CTX_cleanup(ctx);
			return -1;
		}
		outl_total += outl;
	}

 	if(sz_in_length % BLOCK_SIZE != 0){
		isSuccess = EVP_DecryptFinal_ex(ctx, sz_out_buff + outl_total, &outl);
		if(!isSuccess){
			dbg("EVP_DecryptFinal_ex() failed\n");
			EVP_CIPHER_CTX_cleanup(ctx);
			return -1; 
		}
		outl_total += outl;
	} 
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);

	if(NULL != sz_in_decode)
	{
		free(sz_in_decode);
	}
	
	memcpy(out_buff, sz_out_buff,outl_total);
	//parse_space_str((char *)sz_out_buff, (char *)out_buff, strlen((char *)sz_out_buff));
	return outl_total;
}

int ssl_aes_encode(const unsigned char *input,const unsigned char *output,int len)
{
	int in_len = strlen((char *)input);

	if( NULL == input || in_len == 0)
		return -1;

	return aes_encrypt_pkcs5pading((unsigned char *)input, in_len, (unsigned char *)SSL_KEY, (unsigned char *)SSL_IV, (unsigned char *)output, len);
}
 
int ssl_aes_decrypt(const unsigned char *input,const unsigned char *output,int len)
{
	int in_len = strlen((char *)input);

	if( NULL == input || in_len == 0)
		return -1;

	return aes_decrypt_pkcs5pading((unsigned char *)input, in_len, (unsigned char *)SSL_KEY, (unsigned char *)SSL_IV, (unsigned char *)output, len);
}
//#endif

