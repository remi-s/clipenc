#ifndef __KEY_MNGT_H
#define __KEY_MNGT_H

#include "clipenc.h"

#define MAX_KEY_SPACE 16

typedef struct key {
	unsigned char key_id[KEY_ID_SIZE];
	unsigned char algo_id[ALGO_ID_SIZE];
	int key_size;
	unsigned char key[MAX_KEY_SIZE];
} sym_key_t;

typedef struct key_space{
	int key_nb;
	sym_key_t key_l[MAX_KEY_SPACE];
} key_space_t;

#endif
