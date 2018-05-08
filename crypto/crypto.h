#ifndef CRYPTO__H
#define CRYPTO__H


/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


/******************************************************************************/


typedef struct {

    EVP_CIPHER_CTX ctx;
    RSA *rsa_pkey;
    EVP_PKEY *pkey;
	FILE *ofile;
    unsigned char buf_out[4096 + EVP_MAX_IV_LENGTH];
} mcrypt_session_t;


/******************************************************************************/


#ifdef __cplusplus
}
#endif


#endif

/******************************************************************************/
