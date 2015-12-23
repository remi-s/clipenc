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


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "clipenc.h"
#include "key_mngt.h"

int gen_key(unsigned char *algo_id, sym_key_t *k) {
	int len;
	
	gen_rand(k->key_id,KEY_ID_SIZE);
	len=get_key_len(algo_id);
	if (len<0)
		return -1;
	k->key_size=len;
	gen_rand(k->key,len);
	memcpy(k->algo_id,algo_id,ALGO_ID_SIZE);
	return 0;

}


void fprint_key(FILE *f, sym_key_t k) {
	int i;
	fprintf(f,"key_id : ");
	for (i=0;i<KEY_ID_SIZE;i++)
		fprintf(f,"%.2x",k.key_id[i]);
	fprintf(f,"\n");
	fprintf(f,"algo_id : ");
	for (i=0;i<ALGO_ID_SIZE;i++)
		fprintf(f,"%.2x",k.algo_id[i]);
	fprintf(f,"\n");
	fprintf(f,"key_len : %i\n",k.key_size);
	fprintf(f,"key val : ");
	for (i=0;i<k.key_size;i++)
		fprintf(f,"%.2x",k.key[i]);
	fprintf(f,"\n");	
}

void fprint_kspace(FILE *f,key_space_t kspace)  {
	int i;
	fprintf(f,"print keyspace ------------\n");
	fprintf(f,"key_space k_nb : %i\n",kspace.key_nb);
	for (i=0;i<kspace.key_nb;i++) {
		fprintf(f,"key[%i] :\n",i);
		fprint_key(f, kspace.key_l[i]);
	}	
}

int fcreate_kspace(char *fname){
	FILE *f;
	int zero=0x00;
	
	f=fopen(fname,"w");
	if (f==NULL)
		return -1;
	fwrite(&zero,1,sizeof(int),f); 
	fclose(f);
	return 0;
}


int fread_kspace(char *fname, key_space_t *k_space){
	FILE *f;
	int k_nb;
	sym_key_t *k;
	unsigned char *key_id;
	unsigned char *algo_id;
	int *key_size;
	unsigned char *key;
	int i=0;
	
	/* TODO : add password for file encryption */
	f=fopen(fname,"r");
	if (f==NULL)
		return -1;
	if (fread(&k_nb,1,sizeof(int),f) != sizeof(int))
		return -1;
	k_space->key_nb=k_nb;
	while (i<k_nb) {
		k=&(k_space->key_l[i]);
		key_id=k->key_id;
		algo_id=k->algo_id;
		key_size=&(k->key_size);
		key=k->key;
		if (fread(key_id,1,KEY_ID_SIZE,f) != KEY_ID_SIZE)
			return -1;
		if (fread(algo_id,1,ALGO_ID_SIZE,f) != ALGO_ID_SIZE)
			return -1;
		if (fread(key_size,1,sizeof(int),f) != sizeof(int))
			return -1;
		if (fread(key,1,*key_size,f) != *key_size)
			return -1;
		i++;
	}
	fclose(f);
	return 0;
}

int fwrite_kspace(char *fname, key_space_t k_space){
	FILE *f;
	int k_nb;
	sym_key_t k;
	unsigned char *key_id;
	unsigned char *algo_id;
	int *key_size;
	unsigned char *key;
	int i=0;
	
	/* TODO : add password for file encryption */	
	f=fopen(fname,"w");
	if (f==NULL)
		return -1;
	k_nb=k_space.key_nb;
	if (fwrite(&k_nb,1,sizeof(int),f) != sizeof(int))
		return -1;
	while (i<k_nb) {
		k=k_space.key_l[i];
		key_id=k.key_id;
		algo_id=k.algo_id;
		key_size=&(k.key_size);
		key=k.key;
		if (fwrite(key_id,1,KEY_ID_SIZE,f) != KEY_ID_SIZE)
			return -1;
		if (fwrite(algo_id,1,ALGO_ID_SIZE,f) != ALGO_ID_SIZE)
			return -1;
		if (fwrite(key_size,1,sizeof(int),f) != sizeof(int))
			return -1;
		if (fwrite(key,1,*key_size,f) != *key_size)
			return -1;
		i++;
	}
	fclose(f);
	return 0;	
}

void init_key_space(key_space_t *k_space){
	k_space->key_nb=0;
}


void cp_key(sym_key_t *k1,sym_key_t *k2) {
	memcpy(k1->key_id,k2->key_id,KEY_ID_SIZE);
	memcpy(k1->algo_id,k2->algo_id,ALGO_ID_SIZE);
	k1->key_size=k2->key_size;
	memcpy(k1->key,k2->key,k1->key_size);
}

void add_key(sym_key_t k, key_space_t *k_space) {
	cp_key(&(k_space->key_l[k_space->key_nb]),&k);
	k_space->key_nb++;
}

void del_key(sym_key_t k, key_space_t *k_space) {
	int i;
	if (k_space->key_nb==0)
		exit(1);
	k_space->key_nb--;
	while (memcmp(k.key_id,(k_space->key_l[i]).key_id,KEY_ID_SIZE)) {
		i++;
	}
	while (i<k_space->key_nb) {
		cp_key(&(k_space->key_l[i]),&(k_space->key_l[i+1]));
	}
}

int get_key(unsigned char *k_id, key_space_t k_space, sym_key_t * k){
	int i, k_nb;
	sym_key_t *k_list;
	sym_key_t k_f;
	
	i=0;
	k_nb=k_space.key_nb;
	k_list=k_space.key_l;
	while (i<k_nb) {
		k_f=k_list[i];
		if (!memcmp(k_f.key_id,k_id,KEY_ID_SIZE)) {
			cp_key(k,&k_f);
			break;
		}
		i++;
	}
	if (i==k_nb)
		return -1;
	else
		return 0;
}

