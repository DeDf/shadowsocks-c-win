/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#include "common.h"

char rsv_frag[3] = {0x00, 0x00, 0x00};

/* read text from local, encrypt and send to server */
int client_do_local_read(int sockfd, struct link *ln)
{
	int ret;

	if (ln->state & LOCAL_SEND_PENDING)
		return 0;

	ret = do_read(sockfd, ln, "text", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		return 0;
	}

	if (ln->state & SS_UDP)
    {
		/* remove rsv(2) + frag(1) */
		if (rm_data(sockfd, ln, "text", 3) == -1)
			goto out;
	}
    else if (!(ln->state & SS_TCP_HEADER_SENT))
    {
		if (add_data(sockfd, ln, "text",
			     ln->cipher, ln->ss_header_len) == -1)
			goto out;
	}

	if (crypto_encrypt(sockfd, ln) == -1)
		goto out;

	ret = do_send(ln->server_sockfd, ln, "cipher", 0);
	if (ret == -2)
    {
		goto out;
	}
    else if (ret == -1)
    {
		ln->state |= SERVER_SEND_PENDING;
	}
    else
    {
		if (!(ln->state & SS_TCP_HEADER_SENT))
			ln->state |= SS_TCP_HEADER_SENT;
	}

	return 0;
out:
	return -1;
}

/* read cipher from server, decrypt and send to local */
int client_do_server_read(int sockfd, struct link *ln)
{
	int ret;

	if (ln->state & SERVER_SEND_PENDING) {
		return 0;
	}

	/* if iv isn't received, wait to receive bigger than iv_len
	 * bytes before go to next step */
	if (ln->state & SERVER_READ_PENDING)
    {
		printf("%s: server read pending", __FUNCTION__);

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
	}
    else
    {
		ret = do_read(sockfd, ln, "cipher", 0);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		}

		if (!(ln->state & SS_IV_RECEIVED)) {
// 			if (ln->cipher_len <= iv_len) {
// 				ln->state |= SERVER_READ_PENDING;
// 				return 0;
// 			}
		}
	}

	if (crypto_decrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_data(sockfd, ln, "text",
			     rsv_frag, sizeof(rsv_frag)) == -1)
			goto out;
	}

	ret = do_send(ln->local_sockfd, ln, "text", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		ln->state |= LOCAL_SEND_PENDING;
	}

	return 0;
out:
	return -1;
}

int client_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd)
    {
        if (client_do_local_read(sockfd, ln) == -1) {
			goto clean;
		}
	}
    else if (sockfd == ln->server_sockfd)
    {
		if (client_do_server_read(sockfd, ln) == -1) {
			goto clean;
		}
	}

	return 0;
clean:
	destroy_link(sockfd);
	return -1;
}

int client_do_pollout(int sockfd, struct link *ln)
{
	int ret;
    char optval;
	int optlen = sizeof(optval);

	/* write to local */
	if (sockfd == ln->local_sockfd)
    {
		if (ln->state & LOCAL_SEND_PENDING)
        {
			ret = do_send(sockfd, ln, "text", 0);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state &= ~LOCAL_SEND_PENDING;
			}

			/* update socks5 state */
			if (!(ln->state & SOCKS5_AUTH_REPLY_SENT))
				ln->state &= SOCKS5_AUTH_REPLY_SENT;
			else if (!(ln->state & SOCKS5_CMD_REPLY_SENT))
				ln->state &= SOCKS5_CMD_REPLY_SENT;

			goto out;
		}
        else {
			//poll_rm(sockfd, POLLOUT);
		}
	}
    else if (sockfd == ln->server_sockfd)
    {
		/* pending connect finished */
		if (!(ln->state & SERVER)) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
				       &optval, (void *)&optlen) == -1) {
				printf("%s: getsockopt() %s",
					  __FUNCTION__, strerror(errno));
				goto clean;
			}

			if (optval == 0) {
				printf("%s: pending connect() finished",
					  __FUNCTION__);
				ln->time = time(NULL);
				ln->state |= SERVER;
			} else {
				printf("%s: pending connect() failed",
					  __FUNCTION__);
				goto clean;
			}
		}

		if (ln->state & SERVER_SEND_PENDING) {
			/* write to server */
			ret = do_send(sockfd, ln, "cipher", 0);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state &= ~SERVER_SEND_PENDING;

				if (!(ln->state & SS_TCP_HEADER_SENT))
					ln->state |= SS_TCP_HEADER_SENT;
				goto out;
			}
		}
        else {
			//poll_rm(sockfd, POLLOUT);
		}
	}

out:
	return 0;
clean:
	printf("%s: close", __FUNCTION__);
	destroy_link(sockfd);
	return -1;
}

DWORD WINAPI ProxyThread(struct link *ln)
{
    int retlen = 0;
    int sockfd = ln->local_sockfd;
    char *buf = (char *)ln->text;
    int buflen = TEXT_BUF_SIZE;

    // 本地 sock5 验证
    {
        struct socks5_auth_reply rep;
        rep.ver = 0x05;

        retlen = recv(sockfd, buf, buflen, 0);
        if (retlen == -1)
            return retlen;

        if (check_socks5_auth_header(buf, retlen))
            rep.method = SOCKS5_METHOD_ERROR;
        else
            rep.method = SOCKS5_METHOD_NOT_REQUIRED;

        send(sockfd, (char *)&rep, sizeof(rep), 0);
    }
    // 本地 sock5 命令
    {
        int cmd;

        retlen = recv(sockfd, buf, buflen, 0);
        if (retlen == -1)
            return retlen;

        if (check_socks5_cmd_header(buf, retlen))
            cmd = SOCKS5_CMD_REP_FAILED;
        else
            cmd = SOCKS5_CMD_REP_SUCCEEDED;

        if (retlen = create_socks5_cmd_reply(sockfd, ln->server, cmd))
            return retlen;
    }

    /* all seem okay, connect to server! */
    if (connect_server(sockfd) == -1)
        return -1;

Loop:
    retlen |= client_do_pollin( sockfd, ln);
    retlen |= client_do_pollout(sockfd, ln);

    if (!retlen)
        goto Loop;  // 没有错误，循环处理

    return retlen;
}

int main(int argc, char **argv)
{
    WSADATA wsaData;
	int listenfd, sockfd;
	int ret = 0;
	struct link *ln;
	struct addrinfo *server_ai = NULL;
	struct addrinfo *local_ai  = NULL;
	struct addrinfo hint;
    HANDLE hThread;
    DWORD dwThreadID;

	check_ss_option(argc, argv, "client");  // 检查命令行参数

    WSAStartup( MAKEWORD( 2, 2 ), &wsaData );

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	ret = GetAddrInfoA(ss_opt.server_addr, ss_opt.server_port, &hint, &server_ai);
	if (ret != 0) {
		printf("getaddrinfo error: %s\n", gai_strerrorA(ret));
		goto out;
	}

	ret = GetAddrInfoA(ss_opt.local_addr, ss_opt.local_port, &hint, &local_ai);
	if (ret != 0) {
		printf("getaddrinfo error: %s\n", gai_strerrorA(ret));
		goto out;
	}

	if (crypto_init(ss_opt.password, ss_opt.method) == -1) {
		ret = -1;
		goto out;
	}

 	ss_init();

	listenfd = do_listen(local_ai, "tcp");
	clients[0].fd = listenfd;

    while (1)
    {
        sockfd = (int)accept(clients[0].fd, NULL, NULL);
        if (sockfd == -1)
        {
            printf("accept error\n");
            break;
        }
        else
        {
            ln = create_link(sockfd, "client");
            if (ln == NULL)
            {
                closesocket(sockfd);
            }
            else
            {
                ln->server = server_ai;
            }
        }

        hThread = CreateThread (NULL,0,(LPTHREAD_START_ROUTINE)ProxyThread,ln,0,&dwThreadID);
        if (hThread)
            CloseHandle(hThread);
	}
 
out:
    crypto_exit();

	if (server_ai)
		freeaddrinfo(server_ai);

	if (local_ai)
		freeaddrinfo(local_ai);
 
    ss_exit();

    WSACleanup();

    getchar();
	if (ret == -1)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
