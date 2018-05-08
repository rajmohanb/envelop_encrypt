/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curses.h>

#include "mcrypto_api.h"


int main (int argc, char **argv) {

	void *session = NULL;
    FILE *rsa_publickey_file, *rsa_privkey_file;
	FILE *f_input, *f_enc_output, *f_dec_output;
    unsigned char buffer[4096]; // 4K is the limit for now
	size_t len;

	fprintf(stdout, "Sample encryption example\n");

    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <PEM RSA Public Key File> <PEM RSA Private Key File> <Clear Text File>\n", argv[0]);
        exit(1);
    }

    rsa_publickey_file = fopen(argv[1], "rb");
    if (!rsa_publickey_file)
    {
        perror(argv[1]);
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        exit(2);
    }

    rsa_privkey_file = fopen(argv[2], "rb");
    if (!rsa_publickey_file)
    {
        perror(argv[2]);
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        exit(2);
    }

    f_input = fopen(argv[3], "rb");
    if (!f_input) {
        /* unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

    /* open and truncate file to zero length or create ciphertext file for writing */
    f_enc_output = fopen("encrypted_file", "wb");
    if (!f_enc_output) {
        /* unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

	session = mcrypto_encrypt_init(rsa_publickey_file, f_enc_output);
	if (!session) {
		fprintf(stderr, "Error initializing mcrypt\n");
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

	fclose(f_input);
	fclose(rsa_publickey_file);
	//fclose(f_enc_output);
	
	fprintf(stdout, "Encryption done, encrypted file name -> encrypted_file\n");
	fprintf(stdout, "Press any key to decrypt the encrypted file\n");
	fflush(stdin);
	getchar();

    f_enc_output = fopen("encrypted_file", "rb");
    if (!f_enc_output) {
        /* unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

    /* open and truncate file to zero length or create ciphertext file for writing */
    f_dec_output = fopen("decrypted_file", "wb");
    if (!f_dec_output) {
        /* unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
		exit(1);
    }

	session = mcrypto_decrypt_init(rsa_privkey_file, f_enc_output, f_dec_output);
	if (!session) {
		fprintf(stderr, "Error initializing mcrypt decrypt\n");
		exit(1);
	}

	printf("File position before decryption: %ld\n", ftell(f_enc_output));

    while ((len = fread(buffer, 1, sizeof(buffer), f_enc_output)) > 0)
    {
        if (!mcrypto_decrypt_process(session, buffer, len))
        {
            fprintf(stderr, "mcrypto_encrypt_process: failed.\n");
			break;
        }
    }

	mcrypto_decrypt_exit(session);

	fclose(rsa_privkey_file);
	//fclose(f_enc_output);
	
	return 0;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

