
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

// #define TEE_KEY_SIZE 1024
// #define TEE_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
// #define TEE_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

void init_ceaserOP(TEEC_Operation *op, char *plaintext, int len){

	// allocate memory
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
	TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);

	// initialize operation 
	op->params[0].tmpref.buffer = plaintext;
	op->params[0].tmpref.size = len;
	op->params[1].value.a = 0;

}

void ceaser_encryption(TEEC_Context *ctx, TEEC_Session *sess, char *plaintext, int len, char *argv, char *ciphertext)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	// read file
	FILE* pFile = fopen(argv, "r");
	// if don't have file, program exit
	if (pFile == NULL){
		return ;
	}

	puts(" file dectect");

	// copy file context to plaintext
	fread(plaintext, 1, sizeof(plaintext), pFile);
	// file close
	fclose(pFile);

	init_ceaserOP(&op,plaintext,len);
	
	printf("========================Encryption========================\n");
	printf("plaintext : %s\n", plaintext);

	// copy text to buffer
	memcpy(op.params[0].tmpref.buffer, plaintext, len);

	// Call function TEE_encryption for secure
	res = TEEC_InvokeCommand(sess, TEEencrypt_CMD_ENC, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	memcpy(ciphertext, op.params[0].tmpref.buffer, len);

	// Create file including encrypted context 
	pFile = fopen("ciphertext.txt", "w");
	fputs(ciphertext,pFile);
	fclose(pFile);
	printf("Ciphertext : %s\n", ciphertext);

	// Create file including encrypted Key
	pFile = fopen("encryptKey.txt", "w");
	int encryptKey = op.params[1].value.a;
	fprintf(pFile, "%d\n", encryptKey);
	fputs(ciphertext,pFile);
	fclose(pFile);
	printf("CipherKey : %d\n", encryptKey);
}

void ceaser_decryption(TEEC_Context *ctx, TEEC_Session *sess, char *plaintext,
		int len, char *argv1,char *argv2, char *ciphertext){
	TEEC_Operation op;
	TEEC_Result res;	
	uint32_t err_origin;
	int encryptkey = 0;

	// read ciphertext file
	FILE* pFile = fopen(argv1, "r");
	// if don't have file, program exit
	if (pFile == NULL){
		return ;
	}
	puts(" ciphertext file dectect");

	// copy file context to plaintext
	fread(ciphertext, 1, sizeof(ciphertext), pFile);
	// file close
	fclose(pFile);

	// read encryptKey file
	pFile = fopen(argv2, "r");
	// if don't have file, program exit
	if (pFile == NULL){
		return ;
	}
	puts(" encryptKey file dectect");

	// copy file context to plaintext
	fscanf(pFile,"%d",&encryptkey);
	// file close
	fclose(pFile);

	init_ceaserOP(&op, plaintext, len);
	printf("========================Decryption========================\n");
	printf("ciphertext : %s\n", ciphertext);

	// copy text to buffer
	memcpy(op.params[0].tmpref.buffer, ciphertext, len);

	op.params[1].value.a = encryptkey;

	// Call function TEE_encryption for secure
	res = TEEC_InvokeCommand(sess, TEEencrypt_CMD_DEC, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	memcpy(plaintext, op.params[0].tmpref.buffer, len);

	// Create file including encrypted context 
	pFile = fopen("plaintext.txt", "w");
	fputs(plaintext,pFile);
	fclose(pFile);
	printf("plaintext : %s\n", plaintext);
}

int main(int argc, char* argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Result res;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;


	if (4 != argc) {
		perror("> complete 4 words (ex. TEEencrypt -e data.txt Caesar or \n \
		TEEencrypt -e data.txt encrypt.txt)");
		return 1;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		errx(1, "!> TEEC_InitializeContext failed with code 0x%x\n", res);
		return res;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "!> TEEC_Opensession failed with code 0x%x origin 0x%x\n", 
			res, err_origin);
		return res;
	}

	if ((strcmp(argv[3],"RSA"))){
		if ((!strcmp(argv[1],"-e")) && (!strcmp(argv[3],"Ceaser"))){
			ceaser_encryption(&ctx,&sess,plaintext,len,argv[2],ciphertext);
		}
		else if ((!strcmp(argv[1],"-d"))){
			ceaser_decryption(&ctx,&sess,plaintext,len,argv[2],argv[3],ciphertext);
		}
	} else {

	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
