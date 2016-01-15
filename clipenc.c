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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "clipenc.h"
#include "key_mngt.h"
#include "crypto.h"



typedef enum {
	ENC,
	DEC,
	KEX
} cmd_type_t;
	
typedef struct cmd{
	cmd_type_t type;
	unsigned char kid[KEY_ID_SIZE];
	unsigned char tag[KEY_ID_SIZE];
	unsigned char iv[MAX_IV_SIZE];
	int iv_len;
	int cmd_res;
} cmd_t;

typedef struct buff{
	int offset;
	int len;
	unsigned char d[MAX_BUFF_SIZE];
} buff_t;

int is_tag(buff_t *buff) {
	int offset;
	unsigned char *d;
	
	offset=buff->offset;
	d=buff->d;
	if ( (!memcmp(d+offset,"<enc",4)) || (!memcmp(d+offset,"<dec",4)) || (!memcmp(d+offset,"<kex",4)) )
		return 1;
	else
		return 0;
}

void parse_tag(buff_t *buff, cmd_t *ctx) {
	unsigned char s_buff[KEY_ID_SIZE+MAX_IV_SIZE+MAX_TAG_SIZE+3];

	read_in_buff(buff, s_buff, 4);
	if (!memcmp(s_buff,"<enc",4))
		ctx->type=DEC;
	if (!memcmp(s_buff,"<kex",4))
		ctx->type=KEX;
	
	if (ctx->type==DEC) {
		int kid_len=0;
		int iv_len=0;
		int dummy;


		/* TODO : replace by a while loop that read the tag, 
		read the value, affect the value with the corresponding tag */
		/* kid=" */
		read_in_buff(buff, s_buff, 6);
		while (buff->d[buff->offset+kid_len]!='"')
			kid_len++; /* TODO : control buff len */
		read_in_buff(buff, s_buff, kid_len);
		b64_dec(s_buff,kid_len,ctx->kid,&dummy);
		read_in_buff(buff, s_buff, 1);
/*
#ifdef DEBUG
		int i_0;
		printf("kid received :");
		for (i_0=0;i_0<dummy;i_0++)
			printf("%.2x",ctx->kid[i_0]);
		printf("\n");	
#endif*/

		/* iv=" */
		read_in_buff(buff, s_buff, 5);
		while (buff->d[buff->offset+iv_len]!='"')
			iv_len++;
		read_in_buff(buff, s_buff, iv_len);		
		b64_dec(s_buff,iv_len,ctx->iv,&dummy);
		read_in_buff(buff, s_buff, 1);		
/*
#ifdef DEBUG
		int i_1;
		printf("iv received :");
		for (i_1=0;i_1<dummy;i_1++)
			printf("%.2x",ctx->iv[i_1]);
		printf("\n");	
#endif*/
		
		if (buff->d[buff->offset]!='>') {
			read_in_buff(buff, s_buff, 5);	
			if (!memcmp(s_buff," tag=",5)) {
				int tag_len=0;
				/* tag=" */ 
				while (buff->d[buff->offset+tag_len]!='"')
					tag_len++;
				read_in_buff(buff, s_buff, tag_len);
				b64_dec(s_buff,iv_len,ctx->iv,&dummy);
				read_in_buff(buff, s_buff, 1);	
			}
		}
	}
	
	while (buff->d[buff->offset]!='>')
		buff->offset++;

	buff->offset++;
}


/* TODO */
void get_pwd(opt_t *opt) {
}


void cypher_process(unsigned char *in, int in_len, unsigned char *out, int *out_len, key_space_t kspace, cmd_t cmd) {
	
	sym_key_t k;
	int buff_len;
	unsigned char buff[MAX_BUFF_SIZE];

#ifdef DEBUG
		int i;
#endif	

	if	(get_key(cmd.kid,kspace,&k)) {
		cmd.cmd_res=1;
		return;
	}



	// TODO : use function ptr 
	if (cmd.type==ENC) {	
#ifdef DEBUG
		fprintf(stderr,"crypto encryption -------------------\n");
		fprintf(stderr,"plaintext input :");
		for (i=0;i<in_len;i++)
			fprintf(stderr,"%.2x",in[i]);
		fprintf(stderr,"\n");
		fprintf(stderr,"key :");
		for (i=0;i<k.key_size;i++)
			fprintf(stderr,"%.2x",k.key[i]);
		fprintf(stderr,"\n");
		fprintf(stderr,"iv :");
		for (i=0;i<cmd.iv_len;i++)
			fprintf(stderr,"%.2x",cmd.iv[i]);
		fprintf(stderr,"\n");
#endif	
		if (!memcmp(k.algo_id,AES_128_CBC_ALGO_ID,ALGO_ID_SIZE)) {	
			aes_cbc_encrypt(in,in_len,buff,&buff_len,k.key,16,cmd.iv);
		}
		else {
			fprintf(stderr,"algorithm not supported\n");
			exit(1);
		}
#ifdef DEBUG
		fprintf(stderr,"encrypted output :");
		for (i=0;i<buff_len;i++)
			fprintf(stderr,"%.2x",buff[i]);
		fprintf(stderr,"\n");
#endif	
		b64_enc(buff,buff_len,out,out_len);

	}
	
	if (cmd.type==DEC) {	
		b64_dec(in,in_len,buff,&buff_len);

#ifdef DEBUG
		fprintf(stderr,"crypto decryption -------------------\n");
		fprintf(stderr,"encrypted input : ");
		for (i=0;i<buff_len;i++)
			fprintf(stderr,"%.2x",buff[i]);
		fprintf(stderr,"\n");
		fprintf(stderr,"key : ");
		for (i=0;i<k.key_size;i++)
			fprintf(stderr,"%.2x",k.key[i]);
		fprintf(stderr,"\n");
		fprintf(stderr,"iv : ");
		for (i=0;i<cmd.iv_len;i++)
			fprintf(stderr,"%.2x",cmd.iv[i]);
		fprintf(stderr,"\n");
#endif
		if (!memcmp(k.algo_id,AES_128_CBC_ALGO_ID,ALGO_ID_SIZE)) {
			aes_cbc_decrypt(buff,buff_len,out,out_len,k.key,16,cmd.iv);
		}
		else {
			fprintf(stderr,"algorithm not supported\n");
			exit(1);
		}
#ifdef DEBUG
		int i;
		fprintf(stderr,"plaintext output : ");
		for (i=0;i<buff_len;i++)
			fprintf(stderr,"%.2x",buff[i]);
		fprintf(stderr,"\n");
#endif		
	}
}



void gen_enc_cmd(cmd_t *ctx, opt_t *opt){
	ctx->type=ENC;
	if (!opt->kid_flag) {
		fprintf(stderr,"no current key selected. Generate key before encryption\n");
		exit(1);
	}
	memcpy(ctx->kid,opt->kid,KEY_ID_SIZE);
	ctx->iv_len=get_iv_len(opt->algo_id);
	gen_rand(ctx->iv,ctx->iv_len);
}


int write_out_buff(buff_t *buff, unsigned char *d, int len){
	if ((buff->offset+len) > buff->len)
		return -1;
	memcpy(buff->d+buff->offset,d,len);
	buff->offset+=len;
	return len;
}

int read_in_buff(buff_t *buff, unsigned char *d, int len) {

	if ((buff->offset+len) > buff->len)
		return -1;
	memcpy(d,buff->d+buff->offset,len);
	
	buff->offset+=len;
	return len;
}

void create_enc_tag(buff_t *out_buff, cmd_t ctx) {
	int len;
	unsigned char s_buff[KEY_ID_SIZE+MAX_IV_SIZE];
	
	write_out_buff(out_buff,"<enc kid=\"",10);
	b64_enc(ctx.kid,KEY_ID_SIZE,s_buff,&len);
	write_out_buff(out_buff,s_buff,len);
	write_out_buff(out_buff,"\" iv=\"",6);
	b64_enc(ctx.iv,ctx.iv_len,s_buff,&len);
	write_out_buff(out_buff,s_buff,len);
	write_out_buff(out_buff,"\">",2);
}

int compute_len(buff_t in_buff){
	int data_len=0;
	int in_offset,in_len;
	int err=1;
	
	in_offset=in_buff.offset;
	in_len=in_buff.len;
	while(in_offset+data_len<in_len) {
		if (in_buff.d[in_offset+data_len]=='<') {
			err=0;
			break;
		}
		data_len++;
	}
	
	if (err) 
		return -1;
	else
		return data_len;
}



void send_process(buff_t *in_buff, buff_t *out_buff, key_space_t kspace, cmd_t ctx, opt_t opt) {
	if (ctx.type == ENC){
		int in_len, out_len;
		in_len=in_buff->len; /* all the buffer is encrypted */
		create_enc_tag(out_buff, ctx);
		cypher_process(in_buff->d+in_buff->offset,in_len,out_buff->d+out_buff->offset,&out_len,kspace,ctx);
		in_buff->offset+=in_len;
		out_buff->offset+=out_len;
		write_out_buff(out_buff,"</enc>",6);
	}
		
}

void rcvd_process(buff_t *in_buff, buff_t *out_buff, key_space_t *kspace, cmd_t *ctx, opt_t *opt) {
	unsigned char s_buff[40];


	while(in_buff->offset<in_buff->len) {
		if (is_tag(in_buff)) {
			parse_tag(in_buff,ctx);
			if (ctx->type==DEC) {
				int in_len,out_len;
				in_len=compute_len(*in_buff);
				if (in_len<0) {
					fprintf(stderr,"final tag </enc> not found\n");
					exit(1);
				}
				cypher_process(in_buff->d+in_buff->offset,in_len,out_buff->d+out_buff->offset,&out_len,*kspace,*ctx);
				in_buff->offset+=in_len;
				out_buff->offset+=out_len;
				// check </enc> tag 
				read_in_buff(in_buff,s_buff,6);
				if (memcmp(s_buff,"</enc>",6)) {
					fprintf(stderr,"final tag </enc> not found\n");
					exit(1);					
				} 
			}
			
			if (ctx->type==KEX) {
				/* TODO */
				//process_kex(d,&offset,&ctx,opt);
			}
		}
		else {
			out_buff->d[out_buff->offset]=in_buff->d[in_buff->offset];
			in_buff->offset++;
			out_buff->offset++;
		}
	}
}

int fcreate_opt(char *fname){
	FILE *f;
	int zero=0x00;
	unsigned char default_algo_id[ALGO_ID_SIZE];
	
	memcpy(default_algo_id,AES_128_CBC_ALGO_ID,ALGO_ID_SIZE);
	f=fopen(fname,"w");
	if (f==NULL)
		return -1;
	fwrite(&zero,1,sizeof(int),f); /* default kid_flag */
	fwrite(default_algo_id, 1, ALGO_ID_SIZE, f);
	fclose(f);
	return 0;
}

int fprint_opt(FILE *f, opt_t opt) {
	int i;

	fprintf(f,"print option --------------\n");
	fprintf(f,"kid_flag :%i\n",opt.kid_flag);
	if (opt.kid_flag) {
		fprintf(f,"kid : ");
		for (i=0;i<KEY_ID_SIZE;i++)
			fprintf(f,"%.2x",opt.kid[i]);
		fprintf(f,"\n");
	}
	fprintf(f,"algo_id : ");	
	for (i=0;i<ALGO_ID_SIZE;i++)
		fprintf(f,"%.2x",opt.algo_id[i]);
	fprintf(f,"\n");
}

int fread_opt(char *fname, opt_t *opt){
	FILE *f;
	int kid_flag;

	f=fopen(fname,"r");
	if (f==NULL)
		return -1;
	if (fread(&kid_flag,1,sizeof(int),f) != sizeof(int))
		return -1;
	opt->kid_flag=kid_flag;
	if (kid_flag) {
		if (fread(opt->kid, 1, KEY_ID_SIZE, f)!= KEY_ID_SIZE) {
			return -1;
		}
	}
	if (fread(opt->algo_id,1,ALGO_ID_SIZE,f) != ALGO_ID_SIZE)
		return -1;	
	fclose(f);
	return 0;
	
}

int fwrite_opt(char *fname, opt_t opt){
	FILE *f;
	int kid_flag;
	
	f=fopen(fname,"w");
	if (f==NULL)
		return -1;
	kid_flag=opt.kid_flag;
	if (fwrite(&kid_flag,1,sizeof(int),f) != sizeof(int))
		return -1;
	if (kid_flag) {
		if (fwrite(opt.kid, 1, KEY_ID_SIZE, f)!= KEY_ID_SIZE) {
			return -1;
		}
	}
	if (fwrite(opt.algo_id,1,ALGO_ID_SIZE,f) != ALGO_ID_SIZE)
		return -1;
	fclose(f);
	return 0;
}

void usage(){
	fprintf(stderr,"\
Usage: clipenc [-e | -d] [-g] [-k USER] [-i FILE_IN] [-o FILE_OUT] [-P PASSWD]  \n\
       [--key_file K_FILE] [--opt_file O_FILE] [--algo ALGO_NAME] [--kid KEY_ID] \n\
       [--reset_key_file] [--reset_opt_file] [--use_pwd] [-h]\n");
fprintf(stderr,"Easy encryption/decryption tool.\n\
\n\
Options:\n\
 -e, --encrypt         encrypt data from standard input or FILE_IN\n\
                       to standard output or FILE_OUT\n\
 -d, --decrypt         decrypt data from standard input or FILE_IN\n\
                       to standard output or FILE_OUT\n\
 -g, --gen_key         generate a new key\n\
 -k, --key_transmit    print the current key for key transmission to USER\n\
 -i, --input_file      use FILE_IN instead of the standard input\n\
 -o, --output_file     use FILE_OUT instead of the standard output\n\
 -P, --pwd             use PASSWD for key file encryption\n\
 --key_file            use K_FILE as the key file instead of the default file\n\
 --opt_file            use O_FILE as the option file instead of the default file\n\
 --algo                select ALGO_NAME as the default encryption algorithm\n\
 --kid                 select KEY_ID as the current key\n\
 --reset_key_file      reset the default key file or K_FILE if specified\n\
                       warning: all the keys stored in the file are erased\n\
 --reset_opt_file      reset the default option file or O_FILE if specified\n\
                       warning: all the option stored in the file are erased\n\
 --use_pwd             encrypt the key file\n\
 -h, --help            display this message\n\
\n\
Examples:\n\
 - generate a new key in the default key file:\n\
 clipenc -g\n\
 - encrypt the message \"hello\" and store it in file msg.txt:\n\
 echo \"hello\" | clipenc -c -o msg.txt\n\
 - decrypt the message msg.txt and print it:\n\
 cat msg.txt | clipenc -d\n\
");
    
}


int main (int argc, char **argv) {
	int c;
	int eflag=0;
	int dflag=0;
	int gflag=0;
	int reset_key_file_flag=0;
	int reset_opt_file_flag=0;
	int use_pwd_flag=0;
	FILE *fin=stdin;
	FILE *fout=stdout;
	char fname[500];
	
	key_space_t kspace;
	opt_t opt;
	buff_t in_buff, out_buff;
	char *home_dir;

    int option_index = 0;
    static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"encrypt", no_argument, 0, 'e'},
		{"decrypt", no_argument, 0, 'd'},
		{"gen_key", no_argument, 0, 'g'},
		{"input_file", required_argument, 0, 'i'},
		{"output_file", required_argument, 0, 'o'},
		{"reset_key_file", no_argument, 0, 0},
		{"reset_opt_file", no_argument, 0, 0},
		{"use_pwd", no_argument, 0, 0 },
		{"algo", required_argument, 0, 0 },
		{"key_file", required_argument, 0, 0 },
		{"opt_file", required_argument, 0, 0 },
		{0,         0,                 0,  0 }
    };
	
	home_dir=getenv("HOME");
	if (home_dir == NULL)
	{
		fprintf(stderr,"error : can't locate home dir\n");
		exit(1);
	}
	snprintf(opt.kspace_name,500,"%s/.clipenc_k",home_dir);
	snprintf(opt.opt_name,500,"%s/.clipenc_opt",home_dir);
	
	opt.kid_flag=0;
	opt.pwd_flag=0;

	in_buff.offset=0;
	out_buff.offset=0;
	out_buff.len=MAX_BUFF_SIZE;
	
	while ((c = getopt_long (argc, argv, "hedgi:o:P:",long_options, &option_index)) != -1) {
		switch (c) {
			case 0:
				if (!strcmp(long_options[option_index].name,"key_file")) {
					snprintf(opt.kspace_name,500,"%s",optarg);
				} else if (!strcmp(long_options[option_index].name,"reset_key_file")){
					reset_key_file_flag=1;
				} else if (!strcmp(long_options[option_index].name,"reset_opt_file")){
					reset_opt_file_flag=1;
				} else if (!strcmp(long_options[option_index].name,"use_pwd")){
					use_pwd_flag=1;
				}
			break;
				
			case 'h':
				usage();
				exit(0);
				break;
			case 'e':
				eflag=1;
				break;
			case 'd':
				dflag=1;
				break;
			case 'g':
				gflag=1;
				break;				
			case 'i':
				snprintf(fname,500,"%s",optarg);
				if ((fin=fopen(fname,"r"))==NULL) {
					fprintf(stderr,"error : can't open file %s\n",fname);
					exit(1);
				}
				break;
			case 'o':
				snprintf(fname,500,"%s",optarg);
				if ((fout=fopen(fname,"w"))==NULL) {
					fprintf(stderr,"error : can't create file %s\n",fname);
					exit(1);
				}
				break;
			case 'p':
				opt.pwd_flag=1;
				snprintf(opt.pwd,500,"%s",optarg);
				break;
				
		}
	}
	if ((access(opt.kspace_name, F_OK ) == -1 )||(reset_key_file_flag)) {
		fprintf(stderr,"generation of key file %s\n",opt.kspace_name);
		fcreate_kspace(opt.kspace_name);
	}
	if ((access(opt.opt_name, F_OK ) == -1 )||(reset_opt_file_flag)) {
		fprintf(stderr,"generation of opt file %s\n",opt.opt_name);
		fcreate_opt(opt.opt_name);
	}
	
	if (use_pwd_flag) {
		fencrypt_kspace(&opt);
	}

	if (fread_kspace(&opt,&kspace) !=0) {
		fprintf(stderr,"error : can't load key_file %s\n",opt.kspace_name);
		exit(1);
	}

	if (fread_opt(opt.opt_name,&opt) !=0) {
		fprintf(stderr,"error : can't load opt_file %s\n",opt.opt_name);
		exit(1);
	}

#ifdef DEBUG
	fprint_kspace(stderr,kspace);
	fprint_opt(stderr,opt);
#endif

	if (eflag && dflag)  {
		usage();
		exit(1);
	}


	if (gflag) {
		sym_key_t k;
		if (gen_key(opt.algo_id,&k)!=0){
			fprintf(stderr,"error : can't create key with algo_id %.2x%.2x\n",opt.algo_id[0], opt.algo_id[1]);
			exit(1);
		}
		add_key(k, &kspace);
		opt.kid_flag=1;
		memcpy(opt.kid,k.key_id,KEY_ID_SIZE);
		// TODO : output the key 
	}

	if (eflag || dflag) {
		int len;
		cmd_t cmd;

		do {
			len=fread(in_buff.d, 1, MAX_BUFF_SIZE-100,fin);
			in_buff.len=len;
			gen_enc_cmd(&cmd, &opt);
			if (eflag) {
				send_process(&in_buff, &out_buff, kspace, cmd, opt);
			} else if (dflag) {
				rcvd_process(&in_buff, &out_buff, &kspace, &cmd, &opt);
			}

			fwrite(out_buff.d, 1, out_buff.offset, fout);
			in_buff.offset=0;
			out_buff.offset=0;
			out_buff.len=MAX_BUFF_SIZE;

		} while (len==MAX_BUFF_SIZE-100);

	}



	if (fwrite_kspace(opt,kspace)!=0) {
		fprintf(stderr,"error : can't save keyspace in file %s\n",opt.kspace_name);
		exit(1);
	}
	fwrite_opt(opt.opt_name,opt);

}	


