#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "keys.h"

#define MAX_BACKLOG 5
#define MAX_PATH_LEN 256
#define chomp(x) (x)[strlen((x))-1]='\0'

typedef struct idkexd_config_st {
	char idkex_dir_path[MAX_PATH_LEN];
	char master_key_path[MAX_PATH_LEN];
	char master_key_name[MAX_PATH_LEN];
	char idkexd_config_name[MAX_PATH_LEN];
	char idkexd_config_path[MAX_PATH_LEN];
	char port[8];
}IDKEXD_CONFIG;

/* default configuration */
IDKEXD_CONFIG conf = {
	"/etc/idkex/",				// idkex_dir_path
	"/etc/idkex/master_key",	// master_key_path
	"master_key",				// master_key_name
	"idkexd_config",			// idkexd_config_name
	"/etc/idkex/idkexd_config",	// idkexd_config_path
	"4001"						// port
};

static void
die_sys(char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(1);
}

static int
check_path(char *path)
{
	FILE *f;

	if (!path || strcmp(path, "") == 0)
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

enum conf_tag {
	tag_port, tag_master_key_path
};

static int
get_conf_tag(char *str)
{
	if (strcmp(str, "port") == 0)
		return tag_port;
	if (strcmp(str, "master_key_path") == 0)
		return tag_master_key_path;
	return -1;
}

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
			case tag_master_key_path:
				strcpy(conf.master_key_path, np);
				break;
		}
	}
	fclose(fp);
}

static int
listen_socket(char *port)
{
	struct addrinfo hints, *res, *ai;
	int err, sock;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((err = getaddrinfo(NULL, port, &hints, &res)) != 0)
		exit(1);

	for (ai = res; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) continue;
		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(sock);
			continue;
		}
		if (listen(sock, MAX_BACKLOG) < 0) {
			close(sock);
			continue;
		}
		freeaddrinfo(res);
		return sock;
	}
	exit(1);
}

static int
recieve_id(char *id, FILE *in)
{
	char buf[BUFSIZ];

	if (!fgets(buf, sizeof(buf), in))
		die_sys("fgets");

	//buf[strlen(buf) - 1] = '\0';
	chomp(buf);
	strcpy(id, buf);
}

static void
send_private_key(PRIVATE_KEY prk, FILE *out)
{
	setvbuf(out, NULL, _IONBF, 0);
	if (!private_key_write_fp(prk, out))
		die_sys("private_key_write_fp");
	fprintf(out, "\n");
}

static void
service(FILE *in, FILE *out)
{
	char buf[BUFSIZ];
	char id[ID_MAX_LEN];
	PUBLIC_KEY puk;
	PRIVATE_KEY prk;
	MASTER_KEY mak;

	public_key_init(puk);
	private_key_init(prk);
	master_key_init(mak);

	recieve_id(id, in);

	public_key_set_id(puk, id);
	public_key_set_point(puk);

	if (!check_path(conf.master_key_path))
		die_sys("check_path");
	master_key_set_from_file(mak, conf.master_key_path);

	private_key_calc(prk, puk, mak);

	/* send private_key */
	send_private_key(prk, out);

	public_key_clear(puk);
	private_key_clear(prk);
	master_key_clear(mak);
}

static void
server_main(int server)
{
	int sock, pid;
	struct sockaddr_storage addr;
	FILE *inf, *outf;

	while (1) {
		socklen_t addrlen = sizeof(addr);

		sock = accept(server, (struct sockaddr*)&addr, &addrlen);
		if (sock < 0) exit(1);

		pid = fork();
		if (pid < 0) exit(1);
		/* The child process */
		if (pid == 0) {
			inf = fdopen(sock, "r");
			outf = fdopen(sock, "w");

			service(inf, outf);
		}
	}
}

int
main(int argc, char *argv[])
{
	int sock;
#ifndef DEBUG
	if (daemon(0, 0) == -1)
		exit(1);
#endif

	if (check_path(conf.idkexd_config_path))
		read_config(conf.idkexd_config_path);

	sock = listen_socket(conf.port);
	server_main(sock);

	return 0;
}
