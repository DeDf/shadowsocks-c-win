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

int MakeKey(unsigned char *password, unsigned char *iv)
{
    int i;
    //
    MD5_CTX mdContext;
    MD5Init (&mdContext);
    MD5Update (&mdContext, password, 6);
    MD5Final (&mdContext);  // 前16字节！

    printf("key=");
    for(i=0; i<16; i++)
    {
        key[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }

    MD5Init (&mdContext);
    MD5Update (&mdContext, key, 16);
    MD5Update (&mdContext, password, 6);
    MD5Final (&mdContext);  // 后16字节!

    for(i=16; i<32; i++)
    {
        key[i] = mdContext.digest[i-16];
        printf("%02X", mdContext.digest[i-16]);
    }
    printf("\n");

    if (iv)
    {
    MD5Init (&mdContext);
    MD5Update (&mdContext, &key[16], 16);
    MD5Update (&mdContext, password, 6);
    MD5Final (&mdContext);

    printf("iv =");
    for(i=0; i<16; i++)
    {
        iv[i] = mdContext.digest[i];
        printf("%02X", mdContext.digest[i]);
    }
    printf("\n");
    }

	key[EVP_MAX_KEY_LENGTH] = '\0';

	return 0;
}

int crypto_init(char *password, char *method)
{
    if (get_method(method) == -1)
        return -1;

	MakeKey(password, NULL);

    private_AES_set_encrypt_key(key, 256, &AESkey); // 初始化Rc2Key

	return 0;
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


// CFB128，128是指AES算法是以128bit为单元处理数据的，与密钥位数无关！
void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, AES_KEY *key,
                           unsigned char iv[16], int *num,
                           int enc, block128_f block)
{
    unsigned int n;
    size_t l = 0;

    n = *num;
    if (enc) {
        while (l<len) {
            if (n == 0) {
                (*block)(iv, iv, key);
            }
            out[l] = iv[n] ^= in[l];
            ++l;
            n = (n+1) % 16;
        }
        *num = n;
    }
    else {
        while (l<len) {
            unsigned char c;
            if (n == 0) {
                (*block)(iv, iv, key);
            }
            out[l] = iv[n] ^ (c = in[l]); iv[n] = c;
            ++l;
            n = (n+1) % 16;
        }
        *num=n;
    }
}


int crypto_encrypt(int sockfd, struct link *ln)
{
    int num = 0;
    EVP_CIPHER_CTX *ctx_p;

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

    CRYPTO_cfb128_encrypt(
        (unsigned char *)ln->ch_cipher,
        (unsigned char *)ln->ch_cipher,
        ln->cipher_len,
        &AESkey,
        ln->local_iv,
        &num,
        1,
        &AES_encrypt);

    return ln->cipher_len;
err:
    printf("%s failed\n", __FUNCTION__);
    return -1;
}

int crypto_decrypt(int sockfd, struct link *ln)
{
    int num = 0;

    EVP_CIPHER_CTX *ctx_p;

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

    CRYPTO_cfb128_encrypt(
        (unsigned char *)ln->cipher,
        (unsigned char *)ln->ch_cipher,
        ln->cipher_len,
        &AESkey,
        ln->orig_LIV,
        &num,
        0,
        &AES_encrypt);

    return ln->cipher_len;
err:
    printf("%s failed\n", __FUNCTION__);
    return -1;
}