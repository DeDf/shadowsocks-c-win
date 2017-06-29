/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"
#include "log.h"

/* read text from remote, encrypt and send to local */
int server_do_remote_read(int sockfd, struct link *ln)
{
	int ret;

	if (ln->state & SERVER_SEND_PENDING)
		return 0;

	ret = do_read(sockfd, ln, "text", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		return 0;
	}

	if (ln->state & SS_UDP) {
			goto out;
	}

	if (crypto_encrypt(sockfd, ln) == -1)
		goto out;

	ret = do_send(ln->local_sockfd, ln, "cipher", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		ln->state |= LOCAL_SEND_PENDING;
	}

	return 0;
out:
	return -1;
}

/* read cipher from local, decrypt and send to server */
int server_do_local_read(int sockfd, struct link *ln)
{
	int ret;

	if (ln->state & LOCAL_SEND_PENDING) {
		return 0;
	}

	/* if iv isn't received, wait to receive bigger than iv_len
	 * bytes before go to next step */
	if (ln->state & LOCAL_READ_PENDING) {
		ret = do_read(sockfd, ln, "cipher", ln->cipher_len);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		}

		if (ln->cipher_len <= iv_len) {
			return 0;
		} else {
			ln->state &= ~SERVER_READ_PENDING;
		}
	} else {
		ret = do_read(sockfd, ln, "cipher", 0);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		}

		if (!(ln->state & SS_IV_RECEIVED)) {
			if (ln->cipher_len <= iv_len) {
				ln->state |= LOCAL_READ_PENDING;
				return 0;
			}
		}
	}

	if (crypto_decrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (check_ss_header(sockfd, ln) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_RECEIVED)) {
		if (check_ss_header(sockfd, ln) == -1)
			goto out;

		ln->state |= SS_TCP_HEADER_RECEIVED;

		if (ln->text_len == 0)
			return 0;
	}

	ret = do_send(ln->server_sockfd, ln, "text", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		ln->state |= SERVER_SEND_PENDING;
	}

	return 0;
out:
	return -1;
}

int server_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd) {
		if (ln->state & SERVER_PENDING) {
			sock_info(sockfd, "%s: server pending",
				  __FUNCTION__);
			goto out;
		} else if (server_do_local_read(sockfd, ln) == -1) {
			goto clean;
		} else {
			goto out;
		}
	} else if (sockfd == ln->server_sockfd) {
		if (ln->state & LOCAL_PENDING) {
			sock_info(sockfd, "%s: local pending",
				  __FUNCTION__);
			goto out;
		} else if (server_do_remote_read(sockfd, ln) == -1) {
			goto clean;
		} else {
			goto out;
		}
	}

out:
	return 0;
clean:
	sock_info(sockfd, "%s: close", __FUNCTION__);
	destroy_link(sockfd);
	return -1;
}

int server_do_pollout(int sockfd, struct link *ln)
{
	int optval, ret;
	int optlen = sizeof(optval);

	/* write to local */
	if (sockfd == ln->local_sockfd) {
		if (ln->state & LOCAL_SEND_PENDING) {
			ret = do_send(sockfd, ln, "cipher", 0);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state &= ~LOCAL_SEND_PENDING;
				goto out;
			}
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	} else {
		/* pending connect finished */
		if (!(ln->state & SERVER)) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
				       &optval, (void *)&optlen) == -1) {
				sock_warn(sockfd, "%s: getsockopt() %s",
					  __FUNCTION__, strerror(errno));
				return -1;
			}

			if (optval == 0) {
				sock_info(sockfd,
					  "%s: pending connect() finished",
					  __FUNCTION__);
				ln->time = time(NULL);
				ln->state |= SERVER;
			} else {
				sock_warn(sockfd,
					  "%s: pending connect() failed",
					  __FUNCTION__);
				goto clean;
			}
		}

		if (ln->state & SERVER_SEND_PENDING) {
			ret = do_send(sockfd, ln, "text", 0);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state &= ~SERVER_SEND_PENDING;
				goto out;
			}
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	}

out:
	return 0;
clean:
	sock_info(sockfd, "%s: close:", __FUNCTION__);
	destroy_link(sockfd);
	return -1;
}

int main(int argc, char **argv)
{
	short revents;
	int i, listenfd, sockfd;
	int ret = 0;
	struct link *ln;
	struct addrinfo *local_ai_tcp = NULL;
	struct addrinfo *local_ai_udp = NULL;
	struct addrinfo hint;

	check_ss_option(argc, argv, "server");

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(ss_opt.local_addr, ss_opt.local_port,
			  &hint, &local_ai_tcp);
	if (ret != 0) {
		printf("getaddrinfo error: %s\n", gai_strerror(ret));
		ret = -1;
		goto out;
	}

	pr_ai_notice(local_ai_tcp, "listening tcp address");

	hint.ai_socktype = SOCK_DGRAM;
	ret = getaddrinfo(ss_opt.local_addr, ss_opt.local_port,
			  &hint, &local_ai_udp);
	if (ret != 0) {
		printf("getaddrinfo error: %s\n", gai_strerror(ret));
		ret = -1;
		goto out;
	}

	pr_ai_notice(local_ai_udp, "udp address");

	if (crypto_init(ss_opt.password, ss_opt.method) == -1) {
		ret = -1;
		goto out;
	}

	ss_init();
	listenfd = do_listen(local_ai_tcp, "tcp");
	clients[0].fd = listenfd;
	clients[0].events = POLLIN;
	listenfd = do_listen(local_ai_udp, "udp");
	clients[1].fd = listenfd;
	clients[1].events = POLLIN;

	while (1) {
		pr_debug("start polling\n");
		ret = poll(clients, nfds, TCP_INACTIVE_TIMEOUT * 1000);
		if (ret == -1) {
			err_exit("poll error");
		} else if (ret == 0) {
			reaper();
			continue;
		}

		if (clients[0].revents & POLLIN) {
			sockfd = accept(clients[0].fd, NULL, NULL);
			if (sockfd == -1) {
				pr_warn("accept error\n");
			} else if (poll_set(sockfd, POLLIN) == -1) {
				close(sockfd);
			} else {
				ln = create_link(sockfd, "server");
				if (ln == NULL) {
					poll_del(sockfd);
					close(sockfd);
				}
			}
		}

		if (clients[1].revents & POLLIN) {
			pr_warn("udp socks5 not supported(for now)\n");
			/* ln = create_link(sockfd, "server"); */
			/* if (ln != NULL) { */
			/* 	check_ss_header(sockfd, ln); */
			/* } */
		}

		for (i = 2; i < nfds; i++) {
			sockfd = clients[i].fd;
			if (sockfd == -1)
				continue;

			revents = clients[i].revents;
			if (revents == 0)
				continue;

			ln = get_link(sockfd);
			if (ln == NULL) {
				sock_warn(sockfd, "close: can't get link");
				close(sockfd);
				continue;
			}

			if (revents & POLLIN) {
				server_do_pollin(sockfd, ln);
			}

			if (revents & POLLOUT) {
				server_do_pollout(sockfd, ln);
			}

			/* suppress the noise */
			/* if (revents & POLLPRI) { */
			/* 	sock_warn(sockfd, "POLLERR"); */
			/* } else if (revents & POLLERR) { */
			/* 	sock_warn(sockfd, "POLLERR"); */
			/* } else if (revents & POLLHUP) { */
			/* 	sock_warn(sockfd, "POLLHUP"); */
			/* } else if (revents & POLLNVAL) { */
			/* 	sock_warn(sockfd, "POLLNVAL"); */
			/* } */
		}

		reaper();
	}

out:
	crypto_exit();

	if (local_ai_tcp)
		freeaddrinfo(local_ai_tcp);

	if (local_ai_udp)
		freeaddrinfo(local_ai_udp);

	ss_exit();

	if (ret == -1)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
