#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <tepla/ec.h>
#include "keys.h"

/*
 * PUBLIC_KEY
 */
void
public_key_init(PUBLIC_KEY k)
{
	k->id = NULL;
	pairing_init(k->p, "ECBN254");
	point_init(k->P, k->p->g1);
	point_init(k->Q, k->p->g2);
}

/* I have to seriously think error handling */
void
public_key_set_id(PUBLIC_KEY k, char *id)
{
	if (!k->id) {
		k->idlen = strlen(id);
		if (!(k->id = (char *)malloc(k->idlen)))
			exit(1);
		strcpy(k->id, id);
	}
}

/* NOTE
 * which hash algorithm is best?
 * have to add a member to PUBLIC_KEY structure?
 * fourth parameter: 80, 112, 128, 192, 256
 */
void
public_key_set_point(PUBLIC_KEY k)
{
	point_map_to_point(k->P, k->id, k->idlen, 80);
	point_map_to_point(k->Q, k->id, k->idlen, 80);
}

int
public_key_set_from_file(PUBLIC_KEY k, char *filename)
{
	FILE *fp;

	if (!(fp = fopen(filename, "r")))
		return 0;

	if (!public_key_set_from_fp(k, fp))
		return 0;

	if (fclose(fp))
		return 0;

	return 1;
}

int
public_key_set_from_fp(PUBLIC_KEY k, FILE *fp)
{
	char id_buf[ID_MAX_LEN];
	char point_buf[POINT_MAX_LEN];

	if (!fgets(id_buf, sizeof(id_buf), fp))
		return 0;
	chomp(id_buf);
	k->idlen = strlen(id_buf);		/* do not count \n */
	k->id = (char *)malloc(k->idlen + 1); /* null character */
	strcpy(k->id, id_buf);

	if (!fgets(point_buf, sizeof(point_buf), fp))
		return 0;

	point_set_str(k->P, point_buf);

	if (!fgets(point_buf, sizeof(point_buf), fp))
		return 0;

	point_set_str(k->Q, point_buf);

	return 1;
}

int
public_key_write_file(PUBLIC_KEY k, char *filename)
{
	FILE *fp;

	if (!(fp = fopen(filename, "w")))
		return 0;

	if (!public_key_write_fp(k, fp))
		return 0;

	if (fclose(fp))
		return 0;

	return 1;
}

int
public_key_write_fp(PUBLIC_KEY k, FILE *fp)
{
	char point_buf[POINT_MAX_LEN];

	if (fprintf(fp, "%s\n", k->id) < 0)
		return 0;

	point_get_str(point_buf, k->P);

	if (fprintf(fp, "%s\n", point_buf) < 0)
		return 0;

	point_get_str(point_buf, k->Q);
	if (fprintf(fp, "%s\n", point_buf) < 0)
		return 0;

	return 1;
}

void
public_key_clear(PUBLIC_KEY k)
{
	SAFE_FREE(k->id);
	point_clear(k->P);
	point_clear(k->Q);
	pairing_clear(k->p);
}

/*
 * PRIVATE_KEY
 */
void
private_key_init(PRIVATE_KEY k)
{
	k->id = NULL;
	pairing_init(k->p, "ECBN254");
	point_init(k->P, k->p->g1);
	point_init(k->Q, k->p->g2);
}

/* I have to think seriously error handling */
void
private_key_set_id(PRIVATE_KEY k, char *id)
{
	if (!k->id) {
		k->idlen = strlen(id);
		if (!(k->id = (char *)malloc(k->idlen)))
			exit(1);
		strcpy(k->id, id);
	}
}

int
private_key_set_from_file(PRIVATE_KEY k, char *filename)
{
	FILE *fp;

	if (!(fp = fopen(filename, "r")))
		return 0;

	if (!private_key_set_from_fp(k, fp))
		return 0;

	if (fclose(fp))
		return 0;

	return 1;
}

int
private_key_set_from_fp(PRIVATE_KEY k, FILE *fp)
{
	char id_buf[ID_MAX_LEN];
	char point_buf[POINT_MAX_LEN];

	if (!fgets(id_buf, sizeof(id_buf), fp))
		return 0;
	chomp(id_buf);
	k->idlen = strlen(id_buf); /* do not count \n */
	k->id = (char *)malloc(k->idlen + 1); /* null character */
	strcpy(k->id, id_buf);

	if (!fgets(point_buf, sizeof(point_buf), fp))
		return 0;

	point_set_str(k->P, point_buf);

	if (!fgets(point_buf, sizeof(point_buf), fp))
		return 0;

	point_set_str(k->Q, point_buf);

	return 1;
}

int
private_key_write_file(PRIVATE_KEY k, char *filename)
{
	FILE *fp;

	if (!(fp = fopen(filename, "w")))
		return 0;

	if (!private_key_write_fp(k, fp))
		return 0;

	if (fclose(fp))
		return 0;

	return 1;
}

int
private_key_write_fp(PRIVATE_KEY k, FILE *fp)
{
	char point_buf[POINT_MAX_LEN];

	if (fprintf(fp, "%s\n", k->id) < 0)
		return 0;

	point_get_str(point_buf, k->P);
	if (fprintf(fp, "%s\n", point_buf) < 0)
		return 0;

	point_get_str(point_buf, k->Q);
	if (fprintf(fp, "%s\n", point_buf) < 0)
		return 0;

	return 1;
}

void
private_key_calc(PRIVATE_KEY prk, PUBLIC_KEY puk, MASTER_KEY mak)
{
	if (puk->id) {
		if (!(prk->id = (char *)malloc(puk->idlen)))
			exit(1);
		strcpy(prk->id, puk->id);
		prk->idlen = puk->idlen;
	}
	point_mul(prk->P, mak->s, puk->P);
	point_mul(prk->Q, mak->s, puk->Q);
}

void
private_key_clear(PRIVATE_KEY k)
{
	SAFE_FREE(k->id);
	point_clear(k->P);
	point_clear(k->Q);
	pairing_clear(k->p);
}

/*
 * MASTER_KEY
 */
void
master_key_init(MASTER_KEY k)
{
	mpz_init(k->s);
}

/* bad implementation */
void
master_key_gen(MASTER_KEY k, unsigned long secbit)
{
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (int)time(NULL));
	mpz_rrandomb(k->s, state, secbit);
	gmp_randclear(state);
}

int
master_key_set_from_file(MASTER_KEY k, char *filename)
{
	FILE *fp;

	if (!(fp = fopen(filename, "r")))
		return 0;

	if (!master_key_set_from_fp(k, fp));
		return 0;

	if (close(fp))
		return 0;

	return 1;
}

static long
get_fsize_fp(FILE *fp)
{
	long fsize;
	rewind(fp);
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);

	return fsize;
}

int
master_key_set_from_fp(MASTER_KEY k, FILE *fp)
{
	char *p;
	long fsize;
	fsize = get_fsize_fp(fp);
	p = (char *)malloc(fsize);

	fread(p, 1, fsize, fp);
	mpz_import(k->s, fsize, 1, 1, 0, 0, p);

	free(p);
	return 0;
}

int
master_key_write_file(MASTER_KEY k, char *filename)
{
	FILE *fp;

	if (!(fp = fopen(filename, "w")))
		return 0;

	if (!master_key_write_fp(k, fp))
		return 0;

	if (fclose(fp))
		return 0;

	return 1;
}

int
master_key_write_fp(MASTER_KEY k, FILE *fp)
{
	char *p;
	int numb = 8;
	int count = (mpz_sizeinbase(k->s, 2) + numb-1) / numb;
	if (!(p = malloc(count)))
		exit(1);
	mpz_export(p, NULL, 1, 1, 0, 0, k->s);

	fwrite(p, 1, count, fp);

	free(p);
	return 1;
}

void
master_key_clear(MASTER_KEY k)
{
	mpz_clear(k->s);
}

/*
 * KEY SHARING
 */
int
calc_key(Element g, PRIVATE_KEY prk, PUBLIC_KEY puk)
{
	int cmp;

	if ((cmp = strcmp(prk->id, puk->id)) == 0)
		return 0;
	else if (cmp > 0)
		pairing_map(g, prk->P, puk->Q, prk->p);
	else
		pairing_map(g, puk->P, prk->Q, prk->p);

	return 1;
}

void
calc_key_print(PRIVATE_KEY prk, PUBLIC_KEY puk, FILE *fp)
{
	Element g;
	char *p;

	element_init(g, prk->p->g3);
	calc_key(g, prk, puk);

	if (!(p = (char *)malloc(element_get_str_length(g))))
		exit(1);
	element_get_str(p, g);
	fprintf(fp, "%s\n", p);

	free(p);
	element_clear(g);
}
