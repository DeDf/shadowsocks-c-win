/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#include "common.h"

// static bool daemonize;
int nfds = DEFAULT_MAX_CONNECTION;
struct pollfd *clients;
struct ss_option ss_opt;
struct link **link_head;

char *optarg;

static void usage_client(const char *name)
{
	printf("Usage: %s [options]\n"
	       "Options:\n"
	       "\t-s,--server_addr server IP address\n"
	       "\t-p,--server_port server Port\n"
	       "\t-u,--local_addr\t local IP address\n"
	       "\t-b,--local_port\t local Port\n"
	       "\t-k,--password\t your password\n"
	       "\t-m,--method\t encryption algorithm(aes-*-cfb, bf-cfb, cast5-cfb, des-cfb, rc2-cfb, rc4, seed-cfb)\n"
	       "\t-h,--help\t print this help information\n", name);
}

static void usage_server(const char *name)
{
	printf("Usage: %s [options]\n"
	       "Options:\n"
	       "\t-u,--local_addr\t local IP address\n"
	       "\t-b,--local_port\t local Port\n"
	       "\t-k,--password\t your password\n"
	       "\t-m,--method\t encryption algorithm(aes-*-cfb, bf-cfb, cast5-cfb, des-cfb, rc2-cfb, rc4, seed-cfb)\n"
	       "\t-h,--help\t print this help information\n", name);
}

static void pr_ss_option(const char *type)
{
	char *server      = NULL;
	char *server_port = NULL;

	if (strcmp(type, "client") == 0)
    {
		server      = ss_opt.server_addr;
		server_port = ss_opt.server_port;
	}

	printf("[ShadowSocks]\n"
		" server address: %s, server port: %s\n"
		" local  address: %s, local  port: %s\n"
		" method: %s\n password: %s\n",
		server, server_port,
		ss_opt.local_addr, ss_opt.local_port, 
		ss_opt.method, ss_opt.password);
}

int getopt_long(int argc, char **argv, const char *optstring, struct option *longopts, void *dump)
{
    static int i = 1;
    int j;
    int opt = '?';

    optarg = NULL;

    if (argc == i)
    {
        if (argc == 1)
            goto Exit;

        opt = -1;
        goto Exit;
    }

    if (strlen(argv[i]) != 2)
        goto Exit;

    opt = argv[i][1];

    for (j = 0; longopts[j].abName; j++)
    {
        if (longopts[j].abName == (char)opt)
        {
            if (longopts[j].NeedArgument)
            {
                optarg = argv[i+1];
                i++;
            }
            break;
        }
    }

Exit:
    i++;
    return opt;
}

static void parse_cmdline(int argc, char **argv, const char *type)
{
	int len, opt;
	int level = -1;
	char missing[128] = "";
	struct option *longopts;
	const char *optstring;
	void (*usage)(const char *name);

	struct option server_long_options[] = {
		{"local_addr", required_argument, 0, 'u'},
		{"local_port", required_argument, 0, 'b'},
		{"password", required_argument, 0, 'k'},
		{"method", required_argument, 0, 'm'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	struct option client_long_options[] = {
		{"server_addr", required_argument, 0, 's'},
		{"server_port", required_argument, 0, 'p'},
		{"local_addr", required_argument, 0, 'u'},
		{"local_port", required_argument, 0, 'b'},
		{"password", required_argument, 0, 'k'},
		{"method", required_argument, 0, 'm'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	if (strcmp(type, "client") == 0)
    {
		longopts = client_long_options;
		optstring = "s:p:u:b:k:m:h";
		usage = usage_client;
	}
    else if (strcmp(type, "server") == 0)
    {
		longopts = server_long_options;
		optstring = "u:b:k:m:h";
		usage = usage_server;
	}
    else
    {
		printf("%s: unknown type\n", __FUNCTION__);
	}

	while (1)
    {
		opt = getopt_long(argc, argv, optstring, longopts, NULL);
		if (opt == -1)
			break;

		switch (opt)
        {
		case 's':
			if (strcmp(type, "server") == 0)
            {
				printf("%s: server doesn't need -s option\n", __FUNCTION__);
				break;
			}

			len = strlen(optarg);
			if (len <= MAX_DOMAIN_LEN) {
				strcpy(ss_opt.server_addr, optarg);
			} else {
				strncpy(ss_opt.server_addr, optarg,
					MAX_DOMAIN_LEN);
				ss_opt.server_addr[MAX_DOMAIN_LEN] = '\0';
			}

			break;
		case 'p':
			if (strcmp(type, "server") == 0) {
				printf("%s: server doesn't need -p option\n", __FUNCTION__);
				break;
			}

			len = strlen(optarg);
			if (len <= MAX_PORT_STRING_LEN) {
				strcpy(ss_opt.server_port, optarg);
			} else {
				strncpy(ss_opt.server_port, optarg,
					MAX_PORT_STRING_LEN);
				ss_opt.server_port[MAX_PORT_STRING_LEN] = '\0';
			}

			break;
		case 'u':
			len = strlen(optarg);
			if (len <= MAX_DOMAIN_LEN) {
				strcpy(ss_opt.local_addr, optarg);
			} else {
				strncpy(ss_opt.local_addr, optarg,
					MAX_DOMAIN_LEN);
				ss_opt.local_addr[MAX_DOMAIN_LEN] = '\0';
			}

			break;
		case 'b':
			len = strlen(optarg);
			if (len <= MAX_PORT_STRING_LEN) {
				strcpy(ss_opt.local_port, optarg);
			} else {
				strncpy(ss_opt.local_port, optarg,
					MAX_PORT_STRING_LEN);
				ss_opt.local_port[MAX_PORT_STRING_LEN] = '\0';
			}

			break;
		case 'k':
			len = strlen(optarg);
			if (len <= MAX_PWD_LEN) {
				strcpy(ss_opt.password, optarg);
			} else {
				strncpy(ss_opt.password, optarg,
					MAX_PWD_LEN);
				ss_opt.password[MAX_PWD_LEN] = '\0';
			}

			break;
		case 'm':
			len = strlen(optarg);
			if (len <= MAX_METHOD_NAME_LEN)
            {
				strcpy(ss_opt.method, optarg);
			} 
            else
            {
				strncpy(ss_opt.method, optarg, MAX_METHOD_NAME_LEN);
				ss_opt.method[MAX_METHOD_NAME_LEN] = '\0';
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (strcmp(type, "client") == 0)
    {
		if (strlen(ss_opt.server_addr) == 0)
			strcat(missing, "-s ");

		if (strlen(ss_opt.server_port) == 0)
			strcat(missing, "-p ");
	}

	if (strlen(ss_opt.local_addr) == 0)
		strcat(missing, "-u ");

	if (strlen(ss_opt.local_port) == 0)
		strcat(missing, "-b ");

	if (strlen(ss_opt.password) == 0)
		strcat(missing, "-k ");

	if (strlen(ss_opt.method) == 0)
		strcat(missing, "-m ");

	if (strlen(missing) != 0)
    {
		printf("Missing parameter(s): %s\n", missing);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

void check_ss_option(int argc, char **argv, const char *type)
{
	parse_cmdline(argc, argv, type);

	pr_ss_option(type);
}

void ss_init(void)  // done!
{
    int i;

	printf("%s: max connection: %d\n", __FUNCTION__, nfds);

	link_head = calloc(nfds, sizeof(void *));
	if (link_head == NULL)
		printf("%s: calloc failed\n", __FUNCTION__);

    for (i = 0; i < nfds; i++)
        link_head[i] = 0;

	clients = calloc(nfds, sizeof(struct pollfd));
	if (clients == NULL)
		printf("%s: calloc failed\n", __FUNCTION__);

	for (i = 0; i < nfds; i++)
		clients[i].fd = -1;
}

void ss_exit(void)  // done!
{
	if (link_head)
		free(link_head);

	if (clients)
		free(clients);
}
 
// void poll_events_string(short events, char *events_str)
// {
// 	if (events & POLLIN) {
// 		if (strlen(events_str) == 0)
// 			strcat(events_str, "POLLIN");
// 		else
// 			strcat(events_str, " POLLIN");
// 	}
// 
// 	if (events & POLLOUT) {
// 		if (strlen(events_str) == 0)
// 			strcat(events_str, "POLLOUT");
// 		else
// 			strcat(events_str, " POLLOUT");
// 	}
// }
// 
// int poll_add(int sockfd, short events)
// {
// 	char events_str[42] = {'\0'};
// 
// 	if (sockfd < 0 || sockfd >= nfds) {
// 		sock_err(sockfd, "%s: illegal sockfd(%d)", __FUNCTION__, sockfd);
// 		return -1;
// 	}
// 
// 	if (clients[sockfd].fd != sockfd) {
// 		sock_warn(sockfd, "%s: sockfd(%d) not in poll",
// 			  __FUNCTION__, sockfd);
// 		return -1;
// 	}
// 
// 	clients[sockfd].events |= events;
// 	poll_events_string(events, events_str);
// 	sock_info(sockfd, "%s: %s", __FUNCTION__, events_str);
// 
// 	return 0;
// }
// 
// int poll_rm(int sockfd, short events)
// {
// 	char events_str[42] = {'\0'};
// 
// 	if (sockfd < 0 || sockfd >= nfds) {
// 		sock_err(sockfd, "%s: illegal sockfd(%d)", __FUNCTION__, sockfd);
// 		return -1;
// 	}
// 
// 	clients[sockfd].events &= ~events;
// 	poll_events_string(events, events_str);
// 	sock_info(sockfd, "%s: %s", __FUNCTION__, events_str);
// 
// 	return 0;
// }
// 
// int poll_del(int sockfd)
// {
// 	if (sockfd < 0 || sockfd >= nfds) {
// 		sock_err(sockfd, "%s: illegal sockfd(%d)", __FUNCTION__, sockfd);
// 		return -1;
// 	}
// 
// 	clients[sockfd].fd = -1;
// 	sock_info(sockfd, "%s: deleted from poll", __FUNCTION__);
// 
// 	return 0;
// }
// 
// /**
//  * time_out - check if it's timed out
//  *
//  * @this: the time_t we want to compare(usually is NOW)
//  * @that: the time_t we want to check
//  * @value: how long we think it's a timeout
//  *
//  * Return: 0 means time out, -1 means not time out
//  */
// static int time_out(time_t this, time_t that, double value)
// {
// 	if (difftime(this, that) > value)
// 		return 0;
// 	else
// 		return -1;
// }

struct link *create_link(int sockfd, const char *type)
{
	struct link *ln;

	ln = calloc(1, sizeof(struct link));
	if (ln == NULL)
		goto err;

	ln->text = malloc(TEXT_BUF_SIZE);
	if (ln->text == NULL)
		goto err;

	ln->cipher = malloc(CIPHER_BUF_SIZE);
	if (ln->cipher == NULL)
		goto err;

	ln->state |= LOCAL;

	ln->local_sockfd = sockfd;
	ln->server_sockfd = -1;
	ln->time = time(NULL);

	if (link_head[sockfd] != NULL) {
		printf("%s: link already exist for sockfd %d\n",
			  __FUNCTION__, sockfd);
		goto err;
	}

	link_head[sockfd] = ln;

	return ln;
err:
	if (ln->text)
		free(ln->text);

	if (ln->cipher)
		free(ln->cipher);

	if (ln)
		free(ln);

	printf("%s: failed\n", __FUNCTION__);
	return NULL;
}
 
struct link *get_link(int sockfd)
{
	if (sockfd < 0 || sockfd >= nfds) {
		printf("%s: invalid sockfd %d", __FUNCTION__, sockfd);
		return NULL;
	}

	if (link_head[sockfd] == NULL) {
		printf("%s: link doesn't exist", __FUNCTION__);
		return NULL;
	}

	return link_head[sockfd];
}

void destroy_link(struct link *ln)
{
	link_head[ln->local_sockfd] = NULL;
	link_head[ln->server_sockfd] = NULL;

	if (ln->local_sockfd >= 0)
		closesocket(ln->local_sockfd);

	if (ln->server_sockfd >= 0)
		closesocket(ln->server_sockfd);

    if (ln->text)
        free(ln->text);

    if (ln->cipher)
        free(ln->cipher);

    if (ln)
        free(ln);
}

/* for udp, we just bind it, since udp can't listen */
int do_listen(struct addrinfo *info, const char *type_str)
{
	int sockfd, type;
	char opt = 1;
	struct addrinfo *lp = info;

	if (strcmp(type_str, "tcp") == 0)
		type = SOCK_STREAM;
	else if (strcmp(type_str, "udp") == 0)
		type = SOCK_DGRAM;
	else
		printf("%s: unknown socket type\n", __FUNCTION__);

	while (lp)
    {
		if (lp->ai_socktype == type)
        {
			//type |= SOCK_NONBLOCK;  // windows没有这个选项
			sockfd = (int)socket(lp->ai_family, type, 0);
			if (sockfd == -1)
				goto err;

			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
				goto err;

			if (bind(sockfd, lp->ai_addr, lp->ai_addrlen) == -1)
				goto err;

			if (type & SOCK_STREAM)
				if (listen(sockfd, SOMAXCONN) == -1)
					goto err;

			return sockfd;
		}

		lp = lp->ai_next;
	}

err:
	printf("do_listen() error\n");
    return 0;
}

int connect_server(int sockfd)
{
	int new_sockfd, ret, type;
	struct link *ln;
	struct addrinfo *ai;

	ln = get_link(sockfd);
	if (ln == NULL)
		return -1;

	if (ln->server_sockfd != -1)
    {
		printf("%s is called twice on link\n", __FUNCTION__);
		return 0;
	}

	if (ln->state & SS_UDP)
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;

	ai = ln->server;
	while (ai)
    {
		if (ai->ai_socktype == type)
        {
			new_sockfd = (int)socket(ai->ai_family, type, 0);
			if (new_sockfd == -1)
				goto err;

			link_head[new_sockfd] = ln;
			ln->server_sockfd = new_sockfd;
			ln->time = time(NULL);
	
			ret = connect(new_sockfd, ai->ai_addr, ai->ai_addrlen);
			if (ret == -1)
            {
				if (errno == WSAEINPROGRESS)
					return 0;
				else
					goto err;
			}

			/* sucessfully connected */
			ln->state |= SERVER;
			printf("%s: connected", __FUNCTION__);
			return 0;
		}

		ai = ai->ai_next;
	}

err:
	printf("connect_server");
	return -1;
}

int add_data(int sockfd, struct link *ln,
	     const char *type, char *data, int size)
{
	char *buf;
	int len;

	if (strcmp(type, "text") == 0)
    {
		buf = ln->text;
		len = ln->text_len;

		if (len + size > TEXT_BUF_SIZE) {
			printf("%s: data exceed max length(%d/%d)",
				  __FUNCTION__, len + size, TEXT_BUF_SIZE);
			return -1;
		}

		ln->text_len += size;
	}
    else if (strcmp(type, "cipher") == 0)
    {
		buf = ln->cipher;
		len = ln->cipher_len;

		if (len + size > CIPHER_BUF_SIZE) {
			printf("%s: data exceed max length(%d/%d)",
				  __FUNCTION__, len + size, CIPHER_BUF_SIZE);
			return -1;
		}

		ln->cipher_len += size;
	}
    else
    {
		printf("%s: unknown type", __FUNCTION__);
		return -1;
	}

	/* if len == 0, no data need to be moved */
	if (len > 0)
		memmove(buf + size, buf, len);

	memcpy(buf, data, size);
	return 0;
}
 
int rm_data(int sockfd, struct link *ln, const char *type, int size)
{
	char *buf;
	int len;

	if (strcmp(type, "text") == 0) {
		buf = ln->text;

		if (ln->text_len < size) {
			printf("%s: size is too big(%d/%d)",
				  __FUNCTION__, size, ln->text_len);
			return -1;
		}

		ln->text_len -= size;
		len = ln->text_len;
	}
    else if (strcmp(type, "cipher") == 0)
    {
		buf = ln->cipher;
		
		if (ln->cipher_len < size)
        {
			printf("%s: size is too big(%d/%d)",
				  __FUNCTION__, size, ln->cipher_len);
			return -1;
		}

		ln->cipher_len -= size;
		len = ln->cipher_len;
	}
    else
    {
		printf("%s: unknown type", __FUNCTION__);
		return -1;
	}

	memmove(buf, buf + size, len);

	return 0;
}
 
// int check_ss_header(int sockfd, struct link *ln)
// {
// 	int ret;
// 	char atyp;
// 	char addr[256];
// 	unsigned short port;
// 	char port_str[6];
// 	short addr_len;
// 	struct ss_header *req;
// 	struct addrinfo hint;
// 	struct addrinfo *res;
// 
// 	memset(&hint, 0, sizeof(hint));
// 	hint.ai_socktype = SOCK_STREAM;
// 
// 	req = (void *)ln->text;
// 
// 	if (ln->state & SS_UDP) {
// 		hint.ai_socktype = SOCK_DGRAM;
// 	} else {
// 		hint.ai_socktype = SOCK_STREAM;
// 	}
// 	
// 	atyp = req->atyp;
// 	if (atyp == SOCKS5_ADDR_IPV4) {
// 		addr_len = 4;
// 
// 		/* atyp(1) + ipv4_addrlen(4) + port(2) */
// 		if (ln->text_len < 7) {
// 			goto too_short;
// 		}
// 
// 		hint.ai_family = AF_INET;
// 
// 		if (inet_ntop(AF_INET, req->dst, addr, sizeof(addr)) == NULL) {
// 			sock_warn(sockfd, "%s: inet_ntop() %s",
// 				  __FUNCTION__, strerror(errno));
// 			return -1;
// 		}
// 
// 		port = ntohs(*(unsigned short *)(req->dst + addr_len));
// 	} else if (atyp == SOCKS5_ADDR_DOMAIN) {
// 		addr_len = req->dst[0];
// 
// 		/* atyp(1) + addr_size(1) + domain_len(addr_len) + port(2) */
// 		if (ln->text_len < 1 + 1 + addr_len + 2)
// 			goto too_short;
// 
// 		hint.ai_family = AF_UNSPEC;
// 		strncpy(addr, req->dst + 1, addr_len);
// 		addr[addr_len] = '\0';
// 		port = ntohs(*(unsigned short *)(req->dst + addr_len + 1));
// 		/* to compute the right data length(except header) */
// 		addr_len += 1;
// 	} else if (atyp == SOCKS5_ADDR_IPV6) {
// 		hint.ai_family = AF_INET6;
// 		addr_len = 16;
// 
// 		if (inet_ntop(AF_INET6, req->dst, addr, sizeof(addr)) == NULL) {
// 			sock_warn(sockfd, "%s: inet_ntop() %s",
// 				  __FUNCTION__, strerror(errno));
// 			return -1;
// 		}
// 
// 		port = ntohs(*(unsigned short *)(req->dst + addr_len));
// 	} else {
// 		sock_warn(sockfd, "%s: ATYP(%d) isn't legal");
// 		return -1;
// 	}
// 
// 	sock_info(sockfd, "%s: remote address: %s; port: %d",
// 		  __FUNCTION__, addr, port);
// 	sprintf(port_str, "%d", port);
// 	ret = getaddrinfo(addr, port_str, &hint, &res);
// 	if (ret != 0) {
// 		sock_warn(sockfd, "getaddrinfo error: %s", gai_strerror(ret));
// 		return -1;
// 	}
// 
// 	if (ln->state & SS_UDP) {
// 		ln->ss_header_len = ln->text_len;
// 	} else {
// 		ln->ss_header_len = 1 + addr_len + 2;
// 		if (rm_data(sockfd, ln, "text", ln->ss_header_len) == -1)
// 			return -1;
// 	}
// 
// 	ln->server = res;
// 
// 	if (connect_server(sockfd) == -1)
// 		return -1;
// 
// 	return 0;
// 
// too_short:
// 	sock_warn(sockfd, "%s: text is too short",
// 		  __FUNCTION__);
// 	return -1;
// }

int check_socks5_auth_header(char *buf, int len)  // done!
{
	struct socks5_auth_request *req;
    unsigned short i;

	if (len < 3) {
		printf("%s: text len is smaller than auth request\n", __FUNCTION__);
		return -1;
	}

	req = (void *)buf;

	if (req->ver != 0x05) {
		printf("%s: VER(%d) is not 5\n", __FUNCTION__, req->ver);
		return -1;
	}

	i = req->nmethods;
	if ((i + 2) != len) {
		printf("%s: NMETHODS(%d) isn't correct\n", __FUNCTION__, i);
		return -1;
	}

	while (i-- > 0)
		if (req->methods[i] == 0x00)  // 需要一个不需要认证的代理
			return 0;

	printf("%s: only support NO AUTHENTICATION\n", __FUNCTION__);
	return -1;
}

int check_socks5_cmd_header(char *buf, int len, struct link *ln)
{
	char cmd, atyp;
	int ss_header_len;
	struct socks5_cmd_request *req;

	req = (void *)buf;

	if (req->ver != 0x05) {
		printf("%s: VER(%d) is not 5\n", __FUNCTION__, req->ver);
		return -1;
	}

	cmd = req->cmd;
	if (cmd == SOCKS5_CONNECT)
    {
		/* nothing to do */
	}
    else if (cmd == SOCKS5_UDP_ASSOCIATE)
    {
		printf("%s: udp associate received\n", __FUNCTION__);
		printf("udp socks5 not supported(for now)\n");
		return -1;
	}
    else
    {
		printf("CMD(%d) isn't supported\n", cmd);
		return -1;
	}

	if (req->rsv != 0x00) {
		printf("RSV is not 0x00\n");
		return -1;
	}

	atyp = req->atyp;
	/* the following magic number 3 is actually ver(1) + cmd(1) +
	 * rsv(1) */
	if (atyp == SOCKS5_ADDR_IPV4) {
		/* atyp(1) + ipv4(4) + port(2) */
		ss_header_len = 1 + 4 + 2;

		if (len < ss_header_len + 3)
			goto too_short;
	}
    else if (atyp == SOCKS5_ADDR_DOMAIN) {
		/* atyp(1) + addr_size(1) + domain_length(req->dst[0]) + port(2) */
		ss_header_len = 1 + 1 + req->dst[0] + 2;

		if (len < ss_header_len + 3)
			goto too_short;
	}
    else if (atyp == SOCKS5_ADDR_IPV6) {
		/* atyp(1) + ipv6_addrlen(16) + port(2) */
		ss_header_len = 1 + 16 + 2;

		if (len < ss_header_len + 3)
			goto too_short;
	}
    else {
		printf("ATYP isn't legal\n");
		return -1;
	}

	/* remove VER, CMD, RSV for shadowsocks protocol - ss tcp header */
	memcpy(ln->ch_cipher, buf+3, ss_header_len);
    ln->cipher_len = ss_header_len;
	return 0;

too_short:
	printf("%s: text is too short", __FUNCTION__);
	return -1;
}

int create_socks5_cmd_reply(int sockfd, struct addrinfo *server, int cmd)
{
	unsigned short port;
	void *addrptr;
	int addr_len;
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);
    char buf[20];
	struct socks5_cmd_reply *rep = (void *)buf;

	rep->ver = 0x05;
	rep->rep = cmd;
	rep->rsv = 0x00;

	if (getpeername(sockfd, (struct sockaddr *)&ss_addr, (void *)&len) == -1)
    {
		printf("%s: getsockname() %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	while (server)
    {
		if (server->ai_family == ss_addr.ss_family)
        {
			if (server->ai_family == AF_INET)
            {
				rep->atyp = SOCKS5_ADDR_IPV4;
				port = ((SA_IN *)server->ai_addr)->sin_port;
				addrptr = &((SA_IN *)server->ai_addr)->sin_addr;
				addr_len = sizeof(struct in_addr);
			}
            else
            {
				rep->atyp = SOCKS5_ADDR_IPV6;
				port = ((SA_IN6 *)server->ai_addr)->sin6_port;
				addrptr = &((SA_IN6 *)server->ai_addr)->sin6_addr;
				addr_len = sizeof(struct in6_addr);
			}
			break;
		}

		server = server->ai_next;
	}

	if (server == NULL)
		return -1;

	memcpy(rep->bnd, addrptr, addr_len);
	memcpy(rep->bnd + addr_len, (void *)&port, sizeof(short));

	len = sizeof(*rep) + addr_len + 2;

	send(sockfd, buf, len, 0);

    if (len > 0)
	    return 0;
    else
        return -1;
}

int do_read(int sockfd, struct link *ln, const char *type, int offset)
{
	int ret, len;
	char *buf;

	if (strcmp(type, "text") == 0)
    {
		buf = (char *)ln->text + offset;
		len = TEXT_BUF_SIZE - offset;
	}
    else if (strcmp(type, "cipher") == 0)
    {
		buf = (char *)ln->cipher + offset;
		/* cipher read only accept text buffer length data, or
		 * it may overflow text buffer */
		len = TEXT_BUF_SIZE - offset;
	}
    else {
		printf("%s: unknown type %s",
			  __FUNCTION__, type);
		return -2;
	}

#define EWOULDBLOCK             WSAEWOULDBLOCK

	ret = recv(sockfd, buf, len, 0);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			printf("%s(%s): recv() %s\n",
				  __FUNCTION__, type, strerror(errno));
			return -2;
		}
		return -1;
	}
    else if (ret == 0) {
		/* recv() returned 0 means the peer has shut down,
		 * return -2 to let the caller do the closing work */
		printf("%s(%s): the peer has shut down",
			   __FUNCTION__, type);
		return -2;
	}

	if (strcmp(type, "text") == 0)
    {
		ln->text_len = ret + offset;
	}
    else if (strcmp(type, "cipher") == 0)
    {
		ln->cipher_len = ret + offset;
	}

	ln->time = time(NULL);
	printf("%s(%s): recv(%d), offset(%d)\n",
		   __FUNCTION__, type, ret, offset);

	return ret;
}

int do_send(int sockfd, struct link *ln, const char *type, int offset)
{
	int ret, len;
	char *buf;

	if (strcmp(type, "text") == 0)
    {
		buf = (char *)ln->text + offset;
		len = ln->text_len - offset;
	}
    else if (strcmp(type, "cipher") == 0)
    {
		buf = (char *)ln->cipher + offset;
		len = ln->cipher_len - offset;
	}
    else
    {
		printf("%s: unknown type %s",
			  __FUNCTION__, type);
		return -2;
	}

#define ENOTCONN    WSAENOTCONN

	ret = send(sockfd, buf, len, 0);

	if (ret == -1)
    {
		if (errno != EAGAIN && errno != EWOULDBLOCK &&
		    errno != ENOTCONN && errno != EPIPE)
        {
			printf("%s(%s): send() %s",
				  __FUNCTION__, type, strerror(errno));
			return -2;
		}
        else
        {
			return -1;
		}
	}

	if (rm_data(sockfd, ln, type, ret) == -1)
		return -2;

	ln->time = time(NULL);

	if (ret != len)
    {
		printf("%s(%s): send() partial send(%d/%d)",
			   __FUNCTION__, type, ret, len);
		return -1;
	}
		
	printf("%s(%s): send(%d), offset(%d)\n",
		   __FUNCTION__, type, ret, offset);

	return ret;
}
