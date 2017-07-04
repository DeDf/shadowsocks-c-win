/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#ifndef SS_CRYPTO_H
#define SS_CRYPTO_H

#include "common.h"

extern char password[MAX_PWD_LEN + 1];
extern char method[MAX_METHOD_NAME_LEN + 1];
extern int iv_len;

typedef void (*block128_f)(const unsigned char *in, unsigned char *out,
                           const AES_KEY *key);

int  crypto_init(char *key, char *method);
int  crypto_encrypt(int sockfd, struct link *ln);
int  crypto_decrypt(int sockfd, struct link *ln);

#endif
