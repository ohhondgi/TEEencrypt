/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// limit key length 
char limitKeyLengh[100];
int random_key;
int root_key = 5;
size_t letters = 'z' - 'a' +1; // number of alpabets

typedef struct __rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
} RSASession;

/*s
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}


/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t __maybe_unused param_types,
		TEE_Param __maybe_unused params[4],
		void **session)
{
	RSASession *sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	DMSG("has been called");

	*session = (void *)sess;
	DMSG("> Session %p: newly allocated\n", *session);

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *session)
{
	/* Get ciphering context from session ID */
	DMSG("> Session %p: release session", session);
	RSASession* sess = (RSASession *)session;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

// static TEE_Result check_parameter_type(uint32_t param_types) {
// 	const uint32_t exp_param_types =
// 		TEE_PARAM_TYPES(
// 				TEE_PARAM_TYPE_MEMREF_INPUT,
// 				TEE_PARAM_TYPE_MEMREF_OUTPUT,
// 				TEE_PARAM_TYPE_NONE,
// 				TEE_PARAM_TYPE_NONE);

// 	DMSG("> Checking parameters...\n");
// 	/* Safely get the invocation parameters */
// 	if (param_types != exp_param_types) {
// 		EMSG("!> Mismatched parameters\n");
// 		return TEE_ERROR_BAD_PARAMETERS;
// 	}
// 	return TEE_SUCCESS;
// }

static TEE_Result generate_random_key(){
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = (random_key%25)+1;
	return TEE_SUCCESS;	
}

static TEE_Result enc_value(TEE_Param params[4])
{


	char * input = (char *)params[0].memref.buffer;
	int input_len = strlen(params[0].memref.buffer);
	char encrypted [64]={0,};

        do{
                TEE_GenerateRandom(&random_key, sizeof(random_key));
                random_key = random_key % 26;
        }while(random_key == 0);
	if(random_key < 0){
		random_key *= -1;
	}

	DMSG("> Random Key Generated \n");
	DMSG(">> Key :  %d\n", random_key);	

	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", input);
	memcpy(encrypted, input, input_len);

	for(int i=0; i<input_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}

	DMSG ("Ciphertext :  %s", encrypted);
	memcpy(input, encrypted, input_len);
	params[1].value.a = random_key + root_key;

	return TEE_SUCCESS;
}

static TEE_Result dec_value(TEE_Param params[4])
{

	char * input = (char *)params[0].memref.buffer;
	int input_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", input);
	memcpy(decrypted, input, input_len);
	random_key = params[1].value.a - root_key;
	DMSG ("encryptkey : %d", random_key);

	for(int i=0; i<input_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(input, decrypted, input_len);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	// if (check_parameter_type(param_types) != TEE_SUCCESS)
	// 	return TEE_ERROR_BAD_PARAMETERS;
	
	switch (cmd_id) {
	case TEEencrypt_CMD_ENC:	 
		return enc_value(params);	
	case TEEencrypt_CMD_DEC:
		return dec_value(params);
	default:
		EMSG("!> Command ID 0x%x is not supported", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
