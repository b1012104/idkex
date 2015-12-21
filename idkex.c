#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include "keys.h"

#define MAX_PATH_LEN 256

static void
die_sys(char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(1);
}

static int
open_connection(char *host, char *service)
{
	int sock;
	struct addrinfo hints, *res, *ai;
	int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(host, service, &hints, &res)) != 0)
		die_sys("getaddrinfo");
	for (ai = res; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
			if (sock < 0)
				continue;
			if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
				close(sock);
				continue;
			}
		freeaddrinfo(res);
		return sock;
	}
	freeaddrinfo(res);
	die_sys("socket/connect");
}

static int
get_private_key(char *path, char *id, char *host, char *port)
{
	int sock;
	char buf[BUFSIZ];
	FILE *inf, *outf, *fp;

	sock = open_connection(host, port);
	if (!(inf = fdopen(sock, "r")))
		die_sys("fdopen");
	if (!(outf = fdopen(sock, "w")))
		die_sys("fdopen");

	fprintf(outf, "%s\n", id);
	fflush(outf);

	if (!(fp = fopen(path, "w")))
		die_sys("fopen");

	/* recieve private key */
	while (fgets(buf, sizeof(buf), inf)) {
		if (strcmp(buf, "\n") == 0) {
			break;
		}
		fprintf(stderr, "%s", buf);
		fprintf(fp, "%s", buf);
	}
	fclose(fp);
	fclose(inf);
	fclose(outf);

	return 1;
}

static void
set_private_key_path(char *prk_path, char *dir_path, char *id)
{
	strcpy(prk_path, dir_path);
	strcat(prk_path, id);
	strcat(prk_path, ".pri");
}

static int
check_path(char *path)
{
	FILE *f;

	if (!path || (strcmp(path, "") == 0))
		return 0;

	if (!(f = fopen(path, "r")))
		return 0;
	fclose(f);
	return 1;
}

static int
check_dir(char *path)
{
	DIR *d;
	struct dirent *dirp;

	if (!(d = opendir(path)))
		return 0;
	closedir(d);
	return 1;
}

typedef struct idkex_config_st {
	char key_dir_path[MAX_PATH_LEN];
	char private_key_path[MAX_PATH_LEN];
	char id[ID_MAX_LEN];
	char tarid[ID_MAX_LEN];
	char config_path[MAX_PATH_LEN];
	char host[256];
	char port[8];
}IDKEX_CONFIG;

/* TODO
 * make a conf init function
 */
IDKEX_CONFIG conf =
	{
	"",						// key_dir_path
	"",						// private_key_path
	"",						// id
	"",						// tarid
	"",						// config_path
	"localhost",			// host
	"4001"					// port
	};

enum conf_tag {
	tag_port, tag_host, tag_private_key
};

static int
get_conf_tag(char *str)
{
	if (strcmp(str, "port") == 0)
		return tag_port;
	if (strcmp(str, "host") == 0)
		return tag_host;
	if (strcmp(str, "private_key") == 0)
		return tag_private_key;
	return -1;
}

/* TODO
 * bad implementation
 */
static void
read_config(char *confpath)
{
	FILE *fp;
	char buf[BUFSIZ];
	char *p, *np;

	if (!(fp = fopen(confpath, "r"))) {
		exit(1);
	}

	while (fgets(buf, sizeof(buf), fp)) {
		p = buf;
		chomp(p);
		if (*p == '#')
			continue;

		if (!(np = strchr(p, (int)' ')))
			continue;
		*np = '\0';
		np++;

		switch (get_conf_tag(p)) {
			case tag_port:
				strcpy(conf.port, np);
				break;
			case tag_host:
				strcpy(conf.host, np);
				break;
			case tag_private_key:
				strcpy(conf.private_key_path, np);
				break;
		}
	}
	fclose(fp);
}

static void
show_usage()
{
	fprintf(stderr, "idkex [options] [id] target_id\n");
	fprintf(stderr, "-p: port\n");
	fprintf(stderr, "-h: host\n");
	fprintf(stderr, "-g: get private key\n");
	fprintf(stderr, "-f: configuration file\n");
	fprintf(stderr, "-P: set private key path\n");
}

static struct option longopts[] = {
	{"get_private_key", required_argument, 0, 'g'},
	{"host", required_argument, 0, 'h'},
	{"port", required_argument, 0, 'p'},
	{"file", required_argument, 0, 'f'},
	{"priavte_key", required_argument, 0, 'P'}
};

int
main(int argc, char *argv[])
{
	int opt;
	PRIVATE_KEY prk;
	PUBLIC_KEY puk;

	private_key_init(prk);
	public_key_init(puk);

	/* TODO
	 * make conf_set_default
	 */
	strcpy(conf.key_dir_path, getenv("HOME"));
	strcat(conf.key_dir_path, "/.idkex/");

	strcpy(conf.config_path, getenv("HOME"));
	strcat(conf.config_path, "/.idkexrc");

	if (argc < 2) {
		show_usage();
		exit(0);
	}

	/* TODO
	 * read ~/.idkexrc
	 * done?
	 */
	if (check_path(conf.config_path))
		read_config(conf.config_path);

	/* TODO
	 * I have to tink options...
	 */
	while ((opt = getopt_long(argc, argv, "g:p:h:f:P:", longopts, NULL)) != -1) {
		switch (opt) {
			case 'g':
				strcpy(conf.id, optarg);
				set_private_key_path(conf.private_key_path, conf.key_dir_path, conf.id);
				/* TODO
				 * check existence of directory
				 */
				if (!check_dir(conf.key_dir_path)) {
					fprintf(stderr, "No such dirctory");
					exit(1);
				}
				get_private_key(conf.private_key_path, conf.id, conf.host, conf.port);
				exit(0);
			case 'p':
				strcpy(conf.port, optarg);
				break;
			case 'h':
				strcpy(conf.host, optarg);
				break;
			case 'f':
				strcpy(conf.config_path, optarg);
				read_config(conf.config_path);
				break;
			case 'P':
				strcpy(conf.private_key_path, optarg);
				break;
			default:
				break;
		}
	}

	if (argc - optind == 1) {
		strcpy(conf.tarid, argv[optind]);
	} else if (argc - optind == 2) {
		strcpy(conf.id, argv[optind]);
		strcpy(conf.tarid, argv[optind + 1]);
		set_private_key_path(conf.private_key_path, conf.key_dir_path, conf.id);
	}

	/*
	 * calc key
	 */
	if (!check_path(conf.private_key_path)) {
		fprintf(stderr, "private_key is not set\n");
		show_usage();
		exit(1);
	}
	private_key_set_from_file(prk, conf.private_key_path);
	public_key_set_id(puk, conf.tarid);
	public_key_set_point(puk);
	calc_key_print(prk, puk, stdout);

	private_key_clear(prk);
	public_key_clear(puk);

	return 0;
}
