#include <stdio.h>
#include "error.h"
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "ckvs_local.h"
#include "util.h"
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define EPSILON 1e-16

int verify_entry(ckvs_entry_t ckvsEntry);
int is_equal(double double1, double double2);
static int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value);
int check_arg_size(int optargc, int threshold);


int ckvs_local_stats(const char* filename, int optargc, _unused char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    int error = check_arg_size(optargc, 0);
    if (error != ERR_NONE){
        return error;
    }
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(CKVS_t));

    if ((error = ckvs_open(filename, &ckvs)) != ERR_NONE){
        return error;
    }
    print_header(&ckvs.header);
    for(size_t i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i){
        if (verify_entry(ckvs.entries[i]) == 1) {
            print_entry(&ckvs.entries[i]);
        }
    }
    ckvs_close(&ckvs);
    return ERR_NONE;
}

int ckvs_local_get(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);
    int error = 0;
    if ((error = check_arg_size(optargc, 2)) != ERR_NONE){
        return error;
    }
    const char* db_key = optargv[0];
    const char* db_pwd = optargv[1];
    error = ckvs_local_getset(filename, db_key, db_pwd, NULL);
    return error;
}

int ckvs_local_set(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    int error = 0;
    if ((error = check_arg_size(optargc, 3)) != ERR_NONE){
        return error;
    }
    const char* db_key = optargv[0];
    const char* db_pwd = optargv[1];
    const char* db_valuefilename = optargv[2];

    char* buffer_ptr = NULL;
    size_t buffer_size = 0;
    error = read_value_file_content(db_valuefilename, &buffer_ptr, &buffer_size);
    if (error != ERR_NONE){
        free(buffer_ptr);
        buffer_ptr = NULL;
        return error;
    }
    error = ckvs_local_getset(filename, db_key, db_pwd, buffer_ptr);
    if (error != ERR_NONE){
        free(buffer_ptr);
        buffer_ptr = NULL;
        return error;
    }
    free(buffer_ptr);
    buffer_ptr = NULL;
    return ERR_NONE;
}

/**
 * @brief function that verifies if a key of an entry is valid or not
 * @param ckvsEntry
 * @param number_entries
 * @return -1 if a key is empty
 * @return 1 if all keys are valid
 */

int verify_entry(ckvs_entry_t ckvsEntry){
    if (strnlen(ckvsEntry.key, EVP_MAX_KEY_LENGTH) == 0){
        return -1;
    }
    return 1;
}
/**
 * @brief function where get and set share their functionalities.
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to get or set
 * @param pwd (const char*) the password of the entry to get or set
 * @param set_value if null, will "get", otherwise "set"
 * @return an error code
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));
    int error = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(error != ERR_NONE){
        return error;
    }

    CKVS_t ckvs;
    memset(&ckvs, 0, sizeof(CKVS_t));
    if ((error = ckvs_open(filename, &ckvs)) != ERR_NONE){
        return error;
    }

    ckvs_entry_t *ckvsEntry= NULL;
    if((error = ckvs_find_entry(&ckvs,key, &mr.auth_key, &ckvsEntry)) != ERR_NONE){
        ckvs_close(&ckvs);
        return error;
    }
    if(set_value != NULL){
        if(RAND_bytes(ckvsEntry->c2.sha,SHA_DIGEST_LENGTH)!= 1){
            ckvs_close(&ckvs);
            return ERR_IO;
        }
    }

    if((error = ckvs_client_compute_masterkey(&mr, &ckvsEntry->c2)) != ERR_NONE){
        ckvs_close(&ckvs);
        return error;
    }

    char sha_masterkey[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&mr.master_key, sha_masterkey);

    //GET
    if (set_value == NULL){
        if(ckvsEntry->value_len == 0){
            ckvs_close(&ckvs);
            return ERR_NO_VALUE;
        }


        error = fseek(ckvs.file, (long) ckvsEntry->value_off, SEEK_SET);
        if(error != 0){
            ckvs_close(&ckvs);
            return error;
        }

        //unsigned char encrypted[CKVS_MAX_ENTRIES];
        unsigned char* encrypted = calloc(CKVS_MAX_ENTRIES, sizeof(char));
        if(encrypted == NULL){
            ckvs_close(&ckvs);
            return ERR_IO;
        }

        size_t ok = fread(encrypted, ckvsEntry->value_len, 1, ckvs.file);
        if (ok != 1){
            free(encrypted);
            ckvs_close(&ckvs);
            return ERR_IO;
        }
        //DEBUG: compare the data sha
        unsigned char* outbuf = NULL;
        outbuf = calloc(ckvsEntry->value_len + EVP_MAX_BLOCK_LENGTH + 1,sizeof(char));
        if(outbuf == NULL){
            free(encrypted);
            ckvs_close(&ckvs);
            return ERR_OUT_OF_MEMORY;
        }
        size_t outbufLen = 0;
        error = ckvs_client_crypt_value(&mr, 0, encrypted, ckvsEntry->value_len,outbuf,
                                        &outbufLen);
        if(error != 0){
            free(encrypted);
            ckvs_close(&ckvs);
            free(outbuf);
            outbuf = NULL;
            return error;
        }
        free(encrypted);
        pps_printf("%s", outbuf);
        free(outbuf);
        outbuf = NULL;
        ckvs_close(&ckvs);
        return error;
    }
    //SET
    else{
        size_t crypted_value_size = strlen(set_value) + EVP_MAX_BLOCK_LENGTH;
        unsigned char* crypted_value = NULL;
        crypted_value = calloc(1, crypted_value_size);
        if(crypted_value == NULL){
            ckvs_close(&ckvs);
            return ERR_OUT_OF_MEMORY;
        }
        size_t outbufLen = 0;

        if((error = ckvs_client_crypt_value(&mr, 1, (const unsigned char*) set_value,
                                strlen(set_value) + 1, crypted_value, &outbufLen) != ERR_NONE)){
            free(crypted_value);
            crypted_value = NULL;
            ckvs_close(&ckvs);
            return error;
        }
        if((error = ckvs_write_encrypted_value(&ckvs, ckvsEntry, crypted_value, outbufLen)) != 0){
            free(crypted_value);
            crypted_value = NULL;
            ckvs_close(&ckvs);
            return error;
        }
        free(crypted_value);
        crypted_value = NULL;
        ckvs_close(&ckvs);
    }

    return ERR_NONE;
}


int ckvs_local_new(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);
    int error = 0;
    if ((error = check_arg_size(optargc, 2)) != ERR_NONE){
        return error;
    }

    const char* db_key = optargv[0];
    const char* db_pwd = optargv[1];
    if(db_key == NULL){
        return ERR_IO;
    }
    if(db_pwd == NULL){
        return ERR_IO;
    }

    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));
    error = ckvs_client_encrypt_pwd(&mr, db_key, db_pwd);
    if(error != ERR_NONE){
        return error;
    }

    CKVS_t ckvs;
    memset(&ckvs, 0, sizeof(CKVS_t));
    if ((error = ckvs_open(filename, &ckvs)) != ERR_NONE){
        return error;
    }

    ckvs_entry_t *ckvsEntry= NULL;
    if ((error = ckvs_new_entry(&ckvs, db_key, &mr.auth_key, &ckvsEntry)) != ERR_NONE){
        ckvs_close(&ckvs);
        return error;
    }

    ckvs_close(&ckvs);
    return error;
}

/**
 * @brief Checks the number of arguments given and if too big
 * @param optargc
 * @param threshold
 * @return
 */
int check_arg_size(int optargc, int threshold){
    if (optargc < threshold){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }
    if (optargc > threshold){
        return ERR_TOO_MANY_ARGUMENTS;
    }
    return ERR_NONE;
}
