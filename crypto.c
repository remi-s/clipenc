#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "clipenc.h"
#include "crypto.h"


int get_iv_len(unsigned char *algo_id){
	if (!memcmp(AES_128_CBC_ALGO_ID,algo_id,ALGO_ID_SIZE))
		return 16;
}

int get_key_len(unsigned char *algo_id){
	if (!memcmp(AES_128_CBC_ALGO_ID,algo_id,ALGO_ID_SIZE))
		return 16;
	else
		return -1;
}	

int gen_rand(unsigned char *out, int len){
	FILE *f;
	f=fopen("/dev/urandom","r");
	if (f==NULL)
		return -1;
	if (fread(out,1,len,f) != len)
		return -1;
	fclose(f);
	return 0;
}

void b64_enc(unsigned char *in, int in_len, unsigned char *out, int *out_len){
	BIO *bio, *b64;
	BUF_MEM *bptr;
	
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines 
	BIO_write(bio, in, in_len);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	memcpy(out, bptr->data, bptr->length);
	*out_len=bptr->length;
}


void b64_dec(unsigned char *in, int in_len, unsigned char *out, int *out_len){
	BIO *bio, *b64;

	bio = BIO_new_mem_buf(in, in_len);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*out_len = BIO_read(bio, out, in_len);

	BIO_free_all(bio);

}

void aes_cbc_encrypt(unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *key, int key_len, unsigned char *iv) {
	
	EVP_CIPHER_CTX ctx;
	int outlen1, outlen2;

	if (key_len==16) {
		/*printf("iv:");
		int i;
		for (i=0;i<16;i++)
			printf("%.2x",iv[i]);*/
		if (EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, iv)!=1) {
			fprintf(stderr,"EVP_EncryptInit fails\n");
			exit(1);
			}
	}  else if (key_len==24) {
		if	(EVP_EncryptInit(&ctx, EVP_aes_192_cbc(), key, iv)!=1) {
			fprintf(stderr,"EVP_EncryptInit fails\n");
			exit(1);
		}		
	} else if (key_len==32) {
		if	(EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv)!=1) {
			fprintf(stderr,"EVP_EncryptInit fails\n");
			exit(1);
		}
	}

	EVP_EncryptUpdate(&ctx, out, &outlen1, in, in_len);
	EVP_EncryptFinal(&ctx, out + outlen1, &outlen2);
	*out_len=outlen1+outlen2;
}

void aes_cbc_decrypt(unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *key, int key_len, unsigned char *iv) {
	EVP_CIPHER_CTX ctx;
	int outlen1, outlen2;
	
	if (key_len==16) {
		if	(EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), key, iv)!=1) {
			fprintf(stderr,"EVP_DecryptInit fails\n");
			exit(1);
		}
	} else if (key_len==24) {
		if	(EVP_DecryptInit(&ctx, EVP_aes_192_cbc(), key, iv)!=1) {
			fprintf(stderr,"EVP_DecryptInit fails\n");
			exit(1);
		}	
	} else if (key_len==32) {
		if	(EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, iv)!=1) {
			fprintf(stderr,"EVP_DecryptInit fails\n");
			exit(1);
		}
	}
	EVP_DecryptUpdate(&ctx, out, &outlen1, in, in_len);
	EVP_DecryptFinal(&ctx, out + outlen1, &outlen2);
	*out_len=outlen1+outlen2;
}
