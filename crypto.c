/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#include "common.h"

int iv_len = EVP_MAX_IV_LENGTH;

// static const EVP_CIPHER *evp_cipher;
static char key[EVP_MAX_KEY_LENGTH];

static const char supported_method[][MAX_METHOD_NAME_LEN] = {
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"bf-cfb",
	/* "camellia-128-cfb", */
	/* "camellia-192-cfb", */
	/* "camellia-256-cfb", */
	"cast5-cfb",
	"des-cfb",
	/* "idea-cfb", */
	"rc2-cfb",
	"rc4",
	"seed-cfb",
	/* "salsa20-ctr", */
};

int get_method(char *method)
{
    int i;
    for (i = 0; i < sizeof(supported_method)/MAX_METHOD_NAME_LEN; i++)
    {
        if (!strcmp(method, supported_method[i]))
        {
            return 0;
        }
    }

    return -1;
}

int MakeKey(char *password)
{
    int i;
    //
    MD5_CTX mdContext;
    MD5Init (&mdContext);
    MD5Update (&mdContext, "fengzi", 6);
    MD5Final (&mdContext);  // 前16字节！

    printf("key=");
    for(i=0; i<16; i++)
    {
        key[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }

    MD5Init (&mdContext);
    MD5Update (&mdContext, key, 16);
    MD5Update (&mdContext, "fengzi", 6);
    MD5Final (&mdContext);  // 后16字节!

    for(i=16; i<32; i++)
    {
        key[i] = mdContext.digest[i-16];
        printf("%02X", mdContext.digest[i-16]);
    }
    printf("\n");

//     char iv[EVP_MAX_IV_LENGTH];
// 
//     MD5Init (&mdContext);
//     MD5Update (&mdContext, &key[16], 16);
//     MD5Update (&mdContext, "fengzi", 6);
//     MD5Final (&mdContext);
// 
//     printf("iv =");
//     for(i=0; i<16; i++)
//     {
//         iv[i] = mdContext.digest[i];
//         printf("%02X", mdContext.digest[i]);
//     }
//     printf("\n");

	key[EVP_MAX_KEY_LENGTH] = '\0';

	return 0;
}

int crypto_init(char *password, char *method)
{
// 	ERR_load_crypto_strings();
// 	OpenSSL_add_all_algorithms();
// 	OPENSSL_config(NULL);
    if (get_method(method) == -1)
        return -1;
	MakeKey(password);


	return 0;
}

void crypto_exit(void)
{
// 	EVP_cleanup();
// 	ERR_free_strings();
}

int add_iv(int sockfd, struct link *ln)
{
	int ret;
	char *iv_p;

	if (sockfd == ln->local_sockfd)
		iv_p = ln->local_iv;
	else if (sockfd == ln->server_sockfd)
		iv_p = ln->server_iv;
	else
		goto err;

	ret = add_data(sockfd, ln, "cipher", iv_p, iv_len);
	if (ret != 0)
		goto err;

	ln->state |= SS_IV_SENT;

	return 0;
err:
	printf("%s failed", __FUNCTION__);
	return -1;
}

/* iv is in the first iv_len byptes of ss tcp/udp header */
int receive_iv(int sockfd, struct link *ln)
{
	int ret;
	char *iv_p;

	if (sockfd == ln->local_sockfd)
		iv_p = ln->local_iv;
	else if (sockfd == ln->server_sockfd)
		iv_p = ln->server_iv;
	else
		goto err;

	memcpy(iv_p, ln->cipher, iv_len);
	ret = rm_data(sockfd, ln, "cipher", iv_len);
	if (ret != 0)
		goto err;

	ln->state |= SS_IV_RECEIVED;

	return 0;
err:
	printf("%s failed", __FUNCTION__);
	return -1;
}

static int check_cipher(int sockfd, struct link *ln, const char *type)
{
	int ret = 0;
	char *iv_p;
	EVP_CIPHER_CTX *ctx_p;

	if (sockfd == ln->local_sockfd)
    {
		iv_p  = ln->local_iv;
		ctx_p = ln->local_ctx;
	}
    else if (sockfd == ln->server_sockfd)
    {
		iv_p  = ln->server_iv;
		ctx_p = ln->server_ctx;
	}
    else {
		goto err;
	}

	if (strcmp(type, "encrypt") == 0 &&
	    !(ln->state & SS_IV_SENT))
    {

    srand((unsigned)time(NULL));
    *(PUSHORT)iv_p     = (USHORT)rand();
    *((PUSHORT)iv_p+1) = (USHORT)rand();
    *((PUSHORT)iv_p+2) = (USHORT)rand();
    *((PUSHORT)iv_p+3) = (USHORT)rand();
    *((PUSHORT)iv_p+4) = (USHORT)rand();
    *((PUSHORT)iv_p+5) = (USHORT)rand();
    *((PUSHORT)iv_p+6) = (USHORT)rand();
    *((PUSHORT)iv_p+7) = (USHORT)rand();
	iv_p[iv_len] = '\0';

// 		ret = EVP_EncryptInit_ex(ctx_p, evp_cipher,
// 					 NULL, (void *)key,
// 					 (void *)iv_p);

// 		if (ret != 1)
// 			goto err;
	}
    else if (strcmp(type, "decrypt") == 0 &&
		   !(ln->state & SS_IV_RECEIVED))
    {
		if (receive_iv(sockfd, ln) == -1)
			goto err;

// 		ret = EVP_DecryptInit_ex(ctx_p, evp_cipher,
// 					 NULL, (void *)key,
// 					 (void *)iv_p);

// 		if (ret != 1)
// 			goto err;
	}

	return 0;
err:
	printf("%s failed\n", __FUNCTION__);
	return -1;
}

int crypto_encrypt(int sockfd, struct link *ln)
{
	EVP_CIPHER_CTX *ctx_p;

	if (check_cipher(sockfd, ln, "encrypt") == -1)
		goto err;

	if (sockfd == ln->local_sockfd)
    {
		ctx_p = ln->local_ctx;
	}
    else if (sockfd == ln->server_sockfd) {
		ctx_p = ln->server_ctx;
	}
    else {
		goto err;
	}

// 	if (EVP_EncryptUpdate(ctx_p, ln->cipher, &ln->cipher_len,
// 			      ln->text, ln->text_len) != 1)
//     {
// 		goto err;
//     }

	if (!(ln->state & SS_IV_SENT))
		if (add_iv(sockfd, ln) == -1)
			goto err;

	/* encryption succeeded, so text buffer is not needed */
	ln->text_len = 0;

	return ln->cipher_len;
err:
	printf("%s failed\n", __FUNCTION__);
	return -1;
}

int crypto_decrypt(int sockfd, struct link *ln)
{
	int len = 0, text_len;
	EVP_CIPHER_CTX *ctx_p;

	if (check_cipher(sockfd, ln, "decrypt") == -1)
		goto err;

	if (sockfd == ln->local_sockfd)
    {
		ctx_p = ln->local_ctx;
	}
    else if (sockfd == ln->server_sockfd)
    {
		ctx_p = ln->server_ctx;
	}
    else
    {
		goto err;
	}

// 	if (EVP_DecryptUpdate(ctx_p, ln->text, &len,
// 			      ln->cipher, ln->cipher_len) != 1)
//     {
// 		goto err;
// 	}

	text_len = len;
	ln->text_len = text_len;
	/* decryption succeeded, so cipher buffer is not needed */
	ln->cipher_len = 0;

	return text_len;
err:
	printf("%s failed\n", __FUNCTION__);
	return -1;
}
