// ckvs_crypto

#include "ckvs.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>
#include <sanitizer/common_interface_defs.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"


int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    char* concatenation = NULL;
    size_t len_key = strnlen(key, CKVS_MAXKEYLEN);
    size_t len_pwd = strlen(pwd);
    concatenation = calloc(1, len_key + len_pwd + 2);
    if(concatenation == NULL){
        return ERR_OUT_OF_MEMORY;
        free(concatenation);
    }
    strncat(concatenation, key, CKVS_MAXKEYLEN);
    strcat(concatenation, "|");
    strcat(concatenation, pwd);

    /*
    if(strnlen(key, CKVS_MAXKEYLEN) + strnlen(pwd, CKVS_MAXKEYLEN) >= 2 * CKVS_MAXKEYLEN){
        return ERR_IO;
    }
     */


    SHA256((const unsigned char*) concatenation, len_key + len_pwd + 1,
           mr->stretched_key.sha);

    unsigned int lengthAuth = 0;
    unsigned int lengthC1 = 0;

    unsigned char* pointHMACauth = HMAC(EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH,
                                        (const unsigned char*) AUTH_MESSAGE, strlen(AUTH_MESSAGE),
                                        mr->auth_key.sha, &lengthAuth);
    unsigned char* pointHMACmasterKey = HMAC(EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH,
                                             (const unsigned char*) C1_MESSAGE, strlen(C1_MESSAGE),
                                             mr->c1.sha, &lengthC1);


    if (pointHMACauth == NULL || pointHMACmasterKey == NULL ||
        lengthAuth != SHA256_DIGEST_LENGTH || lengthC1 != SHA256_DIGEST_LENGTH){
        free(concatenation);
        concatenation = NULL;
        return ERR_INVALID_COMMAND;
    }
    free(concatenation);
    concatenation = NULL;
    return ERR_NONE;
}

int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2){
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);
    unsigned int length_mk = 0;
    HMAC(EVP_sha256(),mr->c1.sha, SHA256_DIGEST_LENGTH,c2->sha,
                                     SHA256_DIGEST_LENGTH, mr->master_key.sha, &length_mk);
    if((length_mk != SHA256_DIGEST_LENGTH)){
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;
}

int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        //__sanitizer_print_stack_trace();
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}
