#include <stdio.h>
#include "error.h"
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "ckvs_local.h"
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define EPSILON 1e-16

int power_of_two(int table_size); //correcteur : que font ces fonctions ici ? ca devrait etre dans cksv_io
int verify_header(const struct ckvs_header* header);
int verify_entry(ckvs_entry_t ckvsEntry);
int is_equal(double double1, double double2);
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value); //correcteur : devrait etre static


int ckvs_local_stats(const char *filename){
    if(filename == NULL){
        return ERR_INVALID_ARGUMENT;
    }

    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(CKVS_t));
    int error;
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

int ckvs_local_get(const char* filename, const char *key, const char *pwd){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
   int error = ckvs_local_getset(filename, key, pwd, NULL); // correcteur : vous pouvez return ckvs_local_getset directement
   return error;
}

int ckvs_local_set(const char *filename, const char *key, const char *pwd, const char *valuefilename){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_NON_NULL(valuefilename);

    int error = 0;
    char* buffer_ptr = NULL;
    size_t buffer_size = 0;
    error = read_value_file_content(valuefilename, &buffer_ptr, &buffer_size);
    if (error != ERR_NONE){
        free(buffer_ptr);
        buffer_ptr = NULL;
        return error;
    }
    error = ckvs_local_getset(filename, key, pwd, buffer_ptr);
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
    if (strlen(ckvsEntry.key) == 0){
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
    //GET
    if (set_value == NULL){
        if((error = ckvs_client_compute_masterkey(&mr, &ckvsEntry->c2)) != ERR_NONE){
            ckvs_close(&ckvs);
            return error;
        }

        error = fseek(ckvs.file, (long) ckvsEntry->value_off, SEEK_SET);
        if(error != 0){
            ckvs_close(&ckvs);
            return error;
        }

        unsigned char encrypted[(size_t) ckvsEntry->value_len];

        size_t ok = fread(encrypted, ckvsEntry->value_len, 1, ckvs.file);
        if (ok != 1){
            return ERR_IO;
        }

        unsigned char outbuf[ckvsEntry->value_len + EVP_MAX_BLOCK_LENGTH];
        size_t outbufLen = 0;
        error = ckvs_client_crypt_value(&mr, 0, encrypted, ckvsEntry->value_len,outbuf,
                                        &outbufLen);
        if(error != 0){
            ckvs_close(&ckvs);
            return error;
        }
        pps_printf("%s", outbuf); // correcteur : attention au printf si chaine pas NULL terminated
        ckvs_close(&ckvs);
        return error;
    }
    //SET
    else{
        if(RAND_bytes(ckvsEntry->c2.sha,SHA_DIGEST_LENGTH)!= 1){
            ckvs_close(&ckvs);
            return ERR_IO;
        }
        size_t crypted_value_size = strlen(set_value) + EVP_MAX_BLOCK_LENGTH;
        unsigned char crypted_value[crypted_value_size];
        if((error = ckvs_client_compute_masterkey(&mr, &ckvsEntry->c2) != ERR_NONE)){
            ckvs_close(&ckvs);
            return error;
        }
        size_t outbutLen = 0;

        if((error = ckvs_client_crypt_value(&mr, 1, (const unsigned char*) set_value,
                                strlen(set_value) + 1, crypted_value, &outbutLen) != ERR_NONE)){
            ckvs_close(&ckvs);
            return error;
        }
        if((error = ckvs_write_encrypted_value(&ckvs, ckvsEntry, crypted_value, outbutLen)) != 0){
            ckvs_close(&ckvs);
            return error;
        }
        ckvs_close(&ckvs);
    }
    return ERR_NONE;
}

