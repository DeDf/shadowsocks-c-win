
#ifndef HEADER_AES_H
#define HEADER_AES_H

typedef unsigned int   u32;
typedef unsigned short u16;
typedef unsigned char   u8;

#define AES_ENCRYPT	1
#define AES_DECRYPT	0

# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

#ifdef  __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */

#define AES_MAXNR 14
typedef struct _AES_KEY {

    unsigned int rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
} AES_KEY;

int private_AES_set_encrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);
int private_AES_set_decrypt_key(const unsigned char *userKey, const int bits,
	AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
	const AES_KEY *key);

#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_AES_H */
