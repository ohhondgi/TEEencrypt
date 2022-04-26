#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H


/*
 * generate new UU
 */
#define TA_TEEencrypt_UUID \
	{ 0x5253c6b9, 0x257f, 0x493a, \
		{ 0xa8, 0xb2, 0x48, 0x5d, 0xf5, 0xa6, 0xe6, 0xd4} }

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)


/* The function IDs implemented in this TA */
#define TEEencrypt_CMD_ENC		1
#define TEEencrypt_CMD_DEC		2


#endif /*TA_TEEENCRYPT_TA_H*/
