#include <openssl/hmac.h>
#include "ckvs_client.h"
#include "ckvs_local.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "error.h"
#include "ckvs_rpc.h"
#include "stdbool.h"
#include <json-c/json.h>
#include <openssl/rand.h>

#define DATA_NAME "data.json"

int ckvs_client_stats(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    int error = check_arg_size(optargc, 0);
    if (error != ERR_NONE) {
        return error;
    }

    ckvs_connection_t ckvsConnection;
    memset(&ckvsConnection, 0, sizeof(ckvs_connection_t));

    error = ckvs_rpc_init(&ckvsConnection, url);
    if (error != ERR_NONE) {
        return error;
    }

    error = ckvs_rpc(&ckvsConnection, "/stats");
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }

    //ETAPE 4
    json_object *str_object = json_tokener_parse(ckvsConnection.resp_buf);
    if (str_object == NULL) {
        json_object_put(str_object);
        pps_printf("ERROR: json parsing is incomplete, NULL was returned\n");
        ckvs_rpc_close(&ckvsConnection);
        return ERR_IO;
    }
    json_object *header = NULL;

    error = json_header_call_check(str_object, "header_string", &header);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }
    const char *string = json_object_get_string(header);
    if (string == NULL) {
        json_object_put(str_object);
        ckvs_rpc_close(&ckvsConnection);
        return ERR_OUT_OF_MEMORY;
    }

    pps_printf("CKVS Header type       : %s\n", string);
    error = json_header_call_check(str_object, "version", &header);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }

    pps_printf("CKVS Header version    : %d\n", json_object_get_int(header));

    error = json_header_call_check(str_object, "table_size", &header);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }
    pps_printf("CKVS Header table_size : %d\n", json_object_get_int(header));

    error = json_header_call_check(str_object, "threshold_entries", &header);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }
    pps_printf("CKVS Header threshold  : %d\n", json_object_get_int(header));

    error = json_header_call_check(str_object, "num_entries", &header);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }
    pps_printf("CKVS Header num_entries: %d\n", json_object_get_int(header));

    error = json_header_call_check(str_object, "keys", &header);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }
    json_object *key = NULL;
    size_t length = json_object_array_length(header);
    for (size_t i = 0; i < length; ++i) {
        key = json_object_array_get_idx(header, i);
        string = json_object_get_string(key);
        if (string == NULL) {
            json_object_put(str_object);
            ckvs_rpc_close(&ckvsConnection);
            return ERR_OUT_OF_MEMORY;
        }
        pps_printf("Key       : %s\n", string);
    }
    json_object_put(str_object);
    ckvs_rpc_close(&ckvsConnection);
    return ERR_NONE;
}

int json_header_call_check(json_object *obj, const char *str, json_object **val) {
    if ((json_object_object_get_ex(obj, str, val) == false)) {
        pps_printf("Error: the key does not exist\n");
        json_object_put(obj);
        return ERR_IO;
    }
    return ERR_NONE;
}

int ckvs_client_get(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    int error = 0;
    if ((error = check_arg_size(optargc, 2)) != ERR_NONE) {
        return error;
    }
    const char *db_key = optargv[0];
    const char *db_pwd = optargv[1];

    ckvs_connection_t ckvsConnection;
    memset(&ckvsConnection, 0, sizeof(ckvs_connection_t));

    //preparation of args and
    error = ckvs_rpc_init(&ckvsConnection, url);
    if (error != ERR_NONE) {
        return error;
    }


    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));
    error = ckvs_client_encrypt_pwd(&mr, db_key, db_pwd);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }

    //format GET
    char str_of_auth[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&mr.auth_key, str_of_auth);
    char *str = calloc(CKVS_MAX_VALUE_LEN_HTTP_QUERY, sizeof(char));
    if (str == NULL) {
        ckvs_rpc_close(&ckvsConnection);
        return ERR_IO;
    }

    char *output = curl_easy_escape(ckvsConnection.curl, db_key, (int) strnlen(db_key, CKVS_MAXKEYLEN));
    if (output == NULL) {
        free(str);
        str = NULL;
        ckvs_rpc_close(&ckvsConnection);
        return ERR_OUT_OF_MEMORY;
    }

    sprintf(str, "/get?key=%s&auth_key=%s", output, str_of_auth);
    //not used anymore
    free(output);
    output = NULL;

    error = ckvs_rpc(&ckvsConnection, str);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        free(str);
        str = NULL;
        return error;
    }

    free(str);
    str = NULL;

    json_object *str_object = json_tokener_parse(ckvsConnection.resp_buf);
    if (str_object == NULL) {
        pps_printf("%s", ckvsConnection.resp_buf);
        ckvs_rpc_close(&ckvsConnection);
        return ERR_IO;
    }

    json_object *c2_obj = NULL;

    error = json_header_call_check(str_object, "c2", &c2_obj);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }

    const char *c2_str = json_object_get_string(c2_obj);
    if (c2_str == NULL) {
        ckvs_rpc_close(&ckvsConnection);
        json_object_put(str_object);
        return ERR_OUT_OF_MEMORY;
    }
    ckvs_sha_t c2_sha = {""};
    if (SHA256_from_string(c2_str, &c2_sha) == -1) {
        ckvs_rpc_close(&ckvsConnection);
        json_object_put(str_object);
        return ERR_IO;
    }

    error = ckvs_client_compute_masterkey(&mr, &c2_sha);
    char sha_masterkey[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&mr.master_key, sha_masterkey);
    if (error != ERR_NONE) {
        json_object_put(str_object);
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }

    json_object *data = NULL;

    error = json_header_call_check(str_object, "data", &data);
    if (error != ERR_NONE) {
        ckvs_rpc_close(&ckvsConnection);
        return error;
    }

    const char *data_str = json_object_get_string(data);
    uint8_t *data_byte = calloc(strlen(data_str) / 2, sizeof(uint8_t));
    if (data_byte == NULL) {
        ckvs_rpc_close(&ckvsConnection);
        json_object_put(str_object);
        return ERR_IO;
    }
    int num_oct = hex_decode(data_str, data_byte);
    if (num_oct == -1) {
        json_object_put(str_object);
        ckvs_rpc_close(&ckvsConnection);
        free(data_byte);
        data_byte = NULL;
        return ERR_IO;
    }

    //allocates buffer to decrypt data in
    unsigned char *data_decrypted = calloc((size_t) num_oct + EVP_MAX_BLOCK_LENGTH, sizeof(char));
    if (data_decrypted == NULL) {
        ckvs_rpc_close(&ckvsConnection);
        free(data_byte);
        data_byte = NULL;
        json_object_put(str_object);
        return ERR_IO;
    }

    size_t outbufLen = 0;
    //decrypts data
    error = ckvs_client_crypt_value(&mr, 0, data_byte, strlen(data_str) / 2,
                                    data_decrypted, &outbufLen);
    if (error != ERR_NONE) {
        json_object_put(str_object);
        ckvs_rpc_close(&ckvsConnection);
        free(data_decrypted);
        free(data_byte);
        data_decrypted = NULL;
        data_byte = NULL;

        return error;
    }
    pps_printf("%s", data_decrypted);
    free(data_decrypted);
    free(data_byte);
    json_object_put(str_object);
    data_decrypted = NULL;
    data_byte = NULL;
    ckvs_rpc_close(&ckvsConnection);
    return ERR_NONE;
}

int ckvs_client_set(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    int error = 0;
    if ((error = check_arg_size(optargc, 3)) != ERR_NONE) {
        return error;
    }
    const char *db_key = optargv[0];
    const char *db_pwd = optargv[1];
    const char *db_valuefilename = optargv[2];

    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));
    //genere auth key
    error = ckvs_client_encrypt_pwd(&mr, db_key, db_pwd);
    if (error != ERR_NONE) {
        return error;
    }

    ckvs_sha_t c2;
    memset(&c2, 0, sizeof(ckvs_sha_t));
    if (RAND_bytes(c2.sha, SHA256_DIGEST_LENGTH) != 1) {
        return ERR_IO;
    }
    if ((error = ckvs_client_compute_masterkey(&mr, &c2)) != ERR_NONE) {
        return error;
    }

    char sha_masterkey[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&mr.master_key, sha_masterkey);

    char *data = NULL;
    size_t data_len = 0;
    //reads the filename
    error = read_value_file_content(db_valuefilename, &data, &data_len);
    if (error != ERR_NONE) {
        free(data);
        data = NULL;
        return error;
    }

    if (data_len == 0) {
        free(data);
        data = NULL;
        return ERR_NO_VALUE;
    }

    size_t crypted_value_size = strlen(data) + EVP_MAX_BLOCK_LENGTH + 1;
    unsigned char *crypted_value = calloc(crypted_value_size, sizeof(char));
    if (crypted_value == NULL) {
        free(data);
        data = NULL;
        return ERR_OUT_OF_MEMORY;
    }

    size_t outbufLen = 0;
    //encrypt the file
    if ((error = ckvs_client_crypt_value(&mr, 1, (const unsigned char *) data,
                                         data_len + 1, crypted_value, &outbufLen) != ERR_NONE)) {
        free(data);
        data = NULL;
        free(crypted_value);
        crypted_value = NULL;
        return error;
    }

    free(data);
    data = NULL;

    ckvs_connection_t ckvsConnection;
    memset(&ckvsConnection, 0, sizeof(ckvs_connection_t));

    //initialisation of connection
    error = ckvs_rpc_init(&ckvsConnection, url);
    if (error != ERR_NONE) {
        free(crypted_value);
        crypted_value = NULL;
        return error;
    }

    char *str = calloc(CKVS_MAX_VALUE_LEN_HTTP_QUERY, sizeof(char));
    if (str == NULL) {
        ckvs_rpc_close(&ckvsConnection);
        free(crypted_value);
        crypted_value = NULL;
        return ERR_IO;
    }

    char *output = curl_easy_escape(ckvsConnection.curl, db_key, 0);
    if (output == NULL) {
        free(str);
        str = NULL;
        free(crypted_value);
        crypted_value = NULL;
        ckvs_rpc_close(&ckvsConnection);
        return ERR_OUT_OF_MEMORY;
    }

    char str_of_auth[SHA256_PRINTED_STRLEN] = "";
    SHA256_to_string(&mr.auth_key, str_of_auth);

    sprintf(str, "/set?key=%s&auth_key=%s&name=%s&offset=0", output, str_of_auth, DATA_NAME);
    free(output);

    char *c2_string = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (c2_string == NULL) {
        free(crypted_value);
        crypted_value = NULL;
        ckvs_rpc_close(&ckvsConnection);
        free(str);
        str = NULL;
        return ERR_IO;
    }
    SHA256_to_string(&c2, c2_string);

    char *hex_encoded_data = calloc(2 * outbufLen + 1, sizeof(char));
    if (hex_encoded_data == NULL) {
        ckvs_rpc_close(&ckvsConnection);
        free(c2_string);
        c2_string = NULL;
        free(crypted_value);
        crypted_value = NULL;
        free(str);
        str = NULL;
        return ERR_IO;
    }
    hex_encode(crypted_value, outbufLen, hex_encoded_data);

    free(crypted_value);
    crypted_value = NULL;

    json_object *main_object = json_object_new_object();

    int verify = json_object_object_add(main_object, "c2", json_object_new_string(c2_string));
    verify += json_object_object_add(main_object, "data", json_object_new_string(hex_encoded_data));

    free(c2_string);
    c2_string = NULL;
    free(hex_encoded_data);
    hex_encoded_data = NULL;

    if (verify != 0) {
        ckvs_rpc_close(&ckvsConnection);
        json_object_put(main_object);
        free(str);
        str = NULL;
        return ERR_IO;
    }


    const char *json_string = json_object_to_json_string(main_object);
    if ((error = ckvs_post(&ckvsConnection, str, json_string)) != ERR_NONE) {
        json_object_put(main_object);
        ckvs_rpc_close(&ckvsConnection);
        free(str);
        str = NULL;
        return error;
    }

    json_object_put(main_object);
    ckvs_rpc_close(&ckvsConnection);
    free(str);
    str = NULL;
    return ERR_NONE;
}

int ckvs_client_new(const char *url, int optargc, char **optargv) {
    return 0;
}
