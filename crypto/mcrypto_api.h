#ifndef MCRYPTO_API__H
#define MCRYPTO_API__H


/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


/******************************************************************************/


void *mcrypto_encrypt_init(FILE *public_key_file, FILE *encfile);


int mcrypto_encrypt_process(void *session, unsigned char *buf, uint32_t buf_len);


void mcrypto_encrypt_exit(void *session);


void *mcrypto_decrypt_init(FILE *private_key_file, FILE *encfile, FILE *decfile);


int mcrypto_decrypt_process(void *session, unsigned char *buf, uint32_t buf_len);


void mcrypto_decrypt_exit(void *session);


/******************************************************************************/


#ifdef __cplusplus
}
#endif


#endif

/******************************************************************************/
