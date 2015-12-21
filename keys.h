#ifndef KEYS_H
#define KEYS_H

#include <tepla/ec.h>
#include <stdio.h>

#define ID_MAX_LEN 256
#define POINT_MAX_LEN 512
#define SAFE_FREE(x) {if ((x)) { free(x); (x) = NULL;}}
#define chomp(x) (x)[strlen((x))-1]='\0'

typedef struct public_key_st {
	char *id;
	size_t idlen;
	EC_PAIRING p;
	EC_POINT P;
	EC_POINT Q;
} PUBLIC_KEY[1];

typedef struct private_key_st {
	char *id;
	size_t idlen;
	EC_PAIRING p;
	EC_POINT P;
	EC_POINT Q;
} PRIVATE_KEY[1];

typedef struct master_key_st {
	mpz_t s;
} MASTER_KEY[1];

/*
 * PUBLIC_KEY
 */
void public_key_init(PUBLIC_KEY k);
void public_key_set_id(PUBLIC_KEY k, char *id);
void public_key_set_point(PUBLIC_KEY k);
int public_key_set_from_file(PUBLIC_KEY k, char *filename);
int public_key_set_from_fp(PUBLIC_KEY k, FILE *fp);
int public_key_write_file(PUBLIC_KEY k, char *filename);
int public_key_write_fp(PUBLIC_KEY k, FILE *fp);
void public_key_clear(PUBLIC_KEY k);

/*
 * PRIVATE_KEY
 */
void private_key_init(PRIVATE_KEY k);
void private_key_set_id(PRIVATE_KEY k, char *id);
int private_key_set_from_file(PRIVATE_KEY k, char *filename);
int private_key_set_from_fp(PRIVATE_KEY k, FILE *fp);
int private_key_write_file(PRIVATE_KEY k, char *filename);
int private_key_write_fp(PRIVATE_KEY k, FILE *fp);
void private_key_calc(PRIVATE_KEY prk, PUBLIC_KEY puk, MASTER_KEY mak);
void private_key_clear(PRIVATE_KEY k);

/*
 * MASTER_KEY
 */
void master_key_init(MASTER_KEY k);
void master_key_gen(MASTER_KEY k, unsigned long secbit);
int master_key_set_from_file(MASTER_KEY k, char *filename);
int master_key_set_from_fp(MASTER_KEY k, FILE *fp);
int master_key_write_file(MASTER_KEY k, char *filename);
int master_key_write_fp(MASTER_KEY k, FILE *fp);
void master_key_clear(MASTER_KEY k);

/*
 * SHARING KEY
 */
int calc_key(Element g, PRIVATE_KEY prk, PUBLIC_KEY puk);
void calc_key_print(PRIVATE_KEY prk, PUBLIC_KEY puk, FILE *fp);

#endif
