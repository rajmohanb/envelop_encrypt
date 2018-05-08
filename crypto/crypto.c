/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************

Disclaimer: sample code, needs memory cleanup and error checking.

******************************************************************************/

#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "crypto.h"


void *mcrypto_encrypt_init(FILE *public_key_file, FILE *encfile) {

	mcrypt_session_t *s;
    int eklen;
    uint32_t eklen_n;
    unsigned char *ek = NULL;
    unsigned char iv[EVP_MAX_IV_LENGTH];

	s = (mcrypt_session_t *) malloc(sizeof(mcrypt_session_t));
	if (!s) {
		return NULL;
	}

    s->rsa_pkey = NULL;
    s->pkey = EVP_PKEY_new();

    if (!PEM_read_RSA_PUBKEY(public_key_file, &(s->rsa_pkey), NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Public Key File.\n");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

    if (!EVP_PKEY_assign_RSA(s->pkey, s->rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

    EVP_CIPHER_CTX_init(&(s->ctx));
    ek = malloc(EVP_PKEY_size(s->pkey));
	if (!ek) {
		return NULL;
	}

    if (!EVP_SealInit(&(s->ctx), 
				EVP_aes_256_cbc(), &ek, &eklen, iv, &(s->pkey), 1))
    {
        fprintf(stderr, "EVP_SealInit: failed.\n");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

	// write out the encrypted key length, then the encrypted key, then 
	// the iv (the IV length is fixed by the cipher we have chosen)
	// note: supporting only one public key cert for now
    eklen_n = htonl(eklen);
	//printf("Encrypting: eklen %d\n", eklen);
    if (fwrite(&eklen_n, sizeof(eklen_n), 1, encfile) != 1)
    {
        perror("output file");
		//TODO: free session context
		return NULL;
    }
    if (fwrite(ek, eklen, 1, encfile) != 1)
    {
        perror("output file");
		//TODO: free session context
		return NULL;
    }
    if (fwrite(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, encfile) != 1)
    {
        perror("Encrypted file");
		//TODO: free session context
		return NULL;
    }

	printf("File position before encryption: %ld\n", ftell(encfile));

	s->ofile = encfile;

    free(ek);

	return s;
}


int mcrypto_encrypt_process(void *session, unsigned char *buf, uint32_t buf_len) {

	int len_out;
	mcrypt_session_t *s = (mcrypt_session_t *)session;

	if (!EVP_SealUpdate(&(s->ctx), s->buf_out, &len_out, buf, buf_len))
	{
        perror("EVP_SealUpdate");
		fprintf(stderr, "EVP_SealUpdate: failed.\n");
        ERR_print_errors_fp(stderr);
		return 0;
	}

	if (fwrite(s->buf_out, len_out, 1, s->ofile) != 1)
	{
		perror("Encrypted file");
        ERR_print_errors_fp(stderr);
		return 0;
	}

	return 1;
}


void mcrypto_encrypt_exit(void *session) {

	int len_out, len;
	mcrypt_session_t *s = (mcrypt_session_t *)session;

    if (!EVP_SealFinal(&(s->ctx), s->buf_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        ERR_print_errors_fp(stderr);
		return;
    }

    len = fwrite(s->buf_out, len_out, 1, s->ofile);
	if (len != 1) 
    {
        perror("output file");
        ERR_print_errors_fp(stderr);
		return;
    }

	// TODO: free everything
	
    EVP_PKEY_free(s->pkey);
	
	fclose(s->ofile);
	free(s);
}



void *mcrypto_decrypt_init(FILE *private_key_file, FILE *encfile, FILE *decfile) {

	mcrypt_session_t *s;
    unsigned char *ek;
    unsigned int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];
 
	s = (mcrypt_session_t *) malloc(sizeof(mcrypt_session_t));
	if (!s) {
		return NULL;
	}

    s->rsa_pkey = NULL;
    s->pkey = EVP_PKEY_new();

    if (!PEM_read_RSAPrivateKey(
				private_key_file, &(s->rsa_pkey), NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Private Key File.\n");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

    if (!EVP_PKEY_assign_RSA(s->pkey, s->rsa_pkey))
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

    EVP_CIPHER_CTX_init(&(s->ctx));
    ek = malloc(EVP_PKEY_size(s->pkey));

    /* extract the encrypted key length, encrypted key and IV */
    if (fread(&eklen_n, sizeof(eklen_n), 1, encfile) != 1)
    {
        perror("input file");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }
    eklen = ntohl(eklen_n);
	//printf("Decrypting eklen %d\n", eklen);
    if (eklen > EVP_PKEY_size(s->pkey))
    {
        fprintf(stderr, "Bad encrypted key length (%u > %d)\n", 
				eklen, EVP_PKEY_size(s->pkey));
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }
    if (fread(ek, eklen, 1, encfile) != 1)
    {
        perror("input file");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }
    if (fread(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), 1, encfile) != 1)
    {
        perror("input file");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

    if (!EVP_OpenInit(&(s->ctx), EVP_aes_256_cbc(), ek, eklen, iv, s->pkey))
    {
        fprintf(stderr, "EVP_OpenInit: failed.\n");
        ERR_print_errors_fp(stderr);
		//TODO: free session context
		return NULL;
    }

	s->ofile = decfile;

    free(ek);

	return s;
}



int mcrypto_decrypt_process(void *session, unsigned char *buf, uint32_t buf_len) {

	int len_out;
	mcrypt_session_t *s = (mcrypt_session_t *)session;

	if (!EVP_OpenUpdate(&(s->ctx), s->buf_out, &len_out, buf, buf_len))
	{
		fprintf(stderr, "EVP_OpenUpdate: failed.\n");
        ERR_print_errors_fp(stderr);
		return 0;
	}

	if (fwrite(s->buf_out, len_out, 1, s->ofile) != 1)
	{
		perror("Decrypted file");
		return 0;
	}

	return 1;
}


void mcrypto_decrypt_exit(void *session) {

	int len_out;
	mcrypt_session_t *s = (mcrypt_session_t *)session;

    if (!EVP_OpenFinal(&(s->ctx), s->buf_out, &len_out))
    {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        ERR_print_errors_fp(stderr);
		return;
    }

    if (fwrite(s->buf_out, len_out, 1, s->ofile) != 1)
    {
        perror("output file");
        ERR_print_errors_fp(stderr);
		return;
    }

	// TODO: free everything
 
	EVP_PKEY_free(s->pkey);

	fclose(s->ofile);
	free(s);
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

