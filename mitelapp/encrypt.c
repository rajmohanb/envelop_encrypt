#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <jansson.h>

#include <mcrypto_api.h>

#include "app.h"

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4



int main(int argc, char *argv[]) {

    FILE *f_public, *f_enc_output, *f_input;
    struct KMS_secret *kek;
	void *session;
    unsigned char buffer[4096]; // 4K is the limit for now
	size_t len;

    /* Make sure user provides the input file */
    if (argc != 2) {
        printf("Usage: %s /path/to/file\n", argv[0]);
        return -1;
    }

    f_input = fopen(argv[1], "rb");
    if (!f_input) {
        /* unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

    f_enc_output = fopen("encrypted_file", "wb");
    if (!f_enc_output) {
        /* unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

    /*
    as soon as application starts, it needs to interact with the KCM and 
    retrieve the secret (KEK) to be used for encryption
    */
    kek = app_startup_get_value("public");
    if (!kek) {
        fprintf(stderr, "Could not get KEK secret, no need to continue ...\n");
        return -1;
    }

	/*#######################################################################*/
    f_public = fopen("public_key.pem", "wb");
    if (!f_public) {
        /* unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

	if (fwrite(kek->memory, kek->size, 1, f_public) != 1) {
		fprintf(stderr, "Writing to public key file failed\n");
		exit(1);
	}

	fclose(f_public);
    f_public = fopen("public_key.pem", "rb");
	/*#######################################################################*/
	
	session = mcrypto_encrypt_init(f_public, f_enc_output);
	if (!session) {
		fprintf(stderr, "crypto library init failed\n");
		exit(1);
	}

    while ((len = fread(buffer, 1, sizeof(buffer), f_input)) > 0)
    {
        if (!mcrypto_encrypt_process(session, buffer, len))
        {
            fprintf(stderr, "mcrypto_encrypt_process: failed.\n");
			break;
        }
    }

	mcrypto_encrypt_exit(session);

	fclose(f_public);
	fclose(f_input);

	return 0;
}
