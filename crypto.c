/*
* Copyright (c) Remi S.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*
*
* In addition, as a special exception, the copyright holders give
* permission to link the code of portions of this program with the
* OpenSSL library under certain conditions as described in each
* individual source file, and distribute linked combinations
* including the two.
* You must obey the GNU General Public License in all respects
* for all of the code used other than OpenSSL. * If you modify
* file(s) with this exception, you may extend this exception to your
* version of the file(s), but you are not obligated to do so. * If you
* do not wish to do so, delete this exception statement from your
* version. * If you delete this exception statement from all source
* files in the program, then also delete it here.
*/


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

void pbkdf2(char *pass, unsigned char *salt, unsigned char *out){
	 PKCS5_PBKDF2_HMAC_SHA1(pass, -1, salt, 128, 100000, 32, out);
}


int file_decrypt(FILE *f, unsigned char *salt, char *pwd, unsigned char *iv, unsigned char *tag, FILE *fout){
	unsigned char key[32];
	unsigned char in_buff[4096];
	unsigned char out_buff[4096];
	int in_len, out_len, ret;	
	EVP_CIPHER_CTX *ctx;

	pbkdf2(pwd,salt,key);

	if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return -1;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		return -1;
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		return -1;

	do { 
		in_len=fread(in_buff,1,4096,f);
		if(!EVP_DecryptUpdate(ctx, out_buff, &out_len, in_buff, in_len))
			return -1;
		fwrite(out_buff,1,out_len,fout);
	} while (in_len==4096);
	
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		return -1;

	ret = EVP_DecryptFinal_ex(ctx, out_buff, &out_len);
	EVP_CIPHER_CTX_free(ctx);
	if (!(ret>0)) {
		return -1;
	}
	return 0;

}

int file_encrypt(FILE *f, unsigned char *salt, char *pwd, unsigned char *iv, FILE *fout, unsigned char *tag){
	unsigned char key[32];
	unsigned char in_buff[4096];
	unsigned char out_buff[4096];
	int in_len, out_len;	
	EVP_CIPHER_CTX *ctx;
	
	pbkdf2(pwd,salt,key);

	if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return -1;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
	 	return -1;
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

	do { 
		in_len=fread(in_buff,1,4096,f);
		if(1 != EVP_EncryptUpdate(ctx, out_buff, &out_len, in_buff, in_len))
			return -1;
		fwrite(out_buff,1,out_len,fout);
	} while (in_len==4096);
	
	if (1 != EVP_EncryptFinal_ex(ctx, out_buff, &out_len)) return -1;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		return -1;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
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
